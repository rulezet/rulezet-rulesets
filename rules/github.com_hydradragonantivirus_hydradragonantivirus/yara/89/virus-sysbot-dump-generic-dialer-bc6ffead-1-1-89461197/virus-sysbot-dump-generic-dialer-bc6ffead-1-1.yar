rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cea20143daa8d57e8fdecfe56e6337c56b2689400d43e10fdb64f69c5bb96f8e"

  strings:
    $s1 = "T*FaNg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}