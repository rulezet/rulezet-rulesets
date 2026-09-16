rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_562 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_562.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "006f3b82d9ee617ccbcbfdf46911a10a4adf457f76785f2667ddca2c6e8d834a"

  strings:
    $s1 = "viLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}