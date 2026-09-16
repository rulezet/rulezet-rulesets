rule Virus_Sysbot_Dump_Generic_Dialer_F020CCE3_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.F020CCE3_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ca95364d4a64d426f37da659194531502e045627e539e73c88159e96ff14d70"

  strings:
    $s1 = "huSh?c" fullword ascii
    $s2 = "SLAb)*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}