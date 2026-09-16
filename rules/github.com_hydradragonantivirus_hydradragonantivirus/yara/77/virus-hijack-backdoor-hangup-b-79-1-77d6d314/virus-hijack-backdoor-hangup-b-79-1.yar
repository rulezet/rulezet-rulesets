rule Virus_Hijack_Backdoor_Hangup_B_79_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_79_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61f913778308b7de8ca08d62c8d87d7df2720e1d3c40db09f3a7ab021906db20"

  strings:
    $s1 = "PHYSICAL;DR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}