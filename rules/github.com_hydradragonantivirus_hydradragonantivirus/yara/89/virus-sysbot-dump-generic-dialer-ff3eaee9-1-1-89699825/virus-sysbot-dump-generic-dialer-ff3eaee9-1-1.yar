rule Virus_Sysbot_Dump_Generic_Dialer_FF3EAEE9_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.FF3EAEE9_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56e1f84fc126c6bc7ed5c96844bdf96298fd9203e154c80d6fb7351af98b6b10"

  strings:
    $s1 = "&$OXEa" fullword ascii
    $s2 = "VG>aLmS" fullword ascii
    $s3 = "guSS:t" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}