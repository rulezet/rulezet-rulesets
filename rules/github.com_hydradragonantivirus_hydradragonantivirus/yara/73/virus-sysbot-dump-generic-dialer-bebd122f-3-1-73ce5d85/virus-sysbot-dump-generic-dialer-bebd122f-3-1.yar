rule Virus_Sysbot_Dump_Generic_Dialer_BEBD122F_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BEBD122F_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71e00c5a1eade66c9fd48eab9516d70b46f77b8c390af265bb66f7603cd121b5"

  strings:
    $s1 = "TURmA(`" fullword ascii
    $s2 = "CHIT`4" fullword ascii
    $s3 = "3]RovE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}