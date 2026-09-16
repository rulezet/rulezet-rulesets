rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_779 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_779.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ca32184a71539f631e8346696b4b8f5af391a3b1645f015903c5626cd81e344"

  strings:
    $s1 = "rand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}