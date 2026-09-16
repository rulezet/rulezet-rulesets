rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_385 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_385.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "424655043b36a51a46ce97c9407693bfb24d4bd760c2c41d382439cbf37e9d80"

  strings:
    $s1 = "AiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}