rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_487 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_487.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3be91b5fe65bbe5518c2ca65f33761cf08599b30049aa19daa05b5743c50a206"

  strings:
    $s1 = "zYiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}