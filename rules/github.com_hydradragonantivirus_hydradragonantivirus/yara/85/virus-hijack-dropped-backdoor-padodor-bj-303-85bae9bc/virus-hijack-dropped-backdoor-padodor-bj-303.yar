rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_303 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_303.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c6fcc47151526b2b4d3ed988215b9e77ce3a1544761fcd5ca2e4fbf1d123265"

  strings:
    $s1 = "Iactive employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}