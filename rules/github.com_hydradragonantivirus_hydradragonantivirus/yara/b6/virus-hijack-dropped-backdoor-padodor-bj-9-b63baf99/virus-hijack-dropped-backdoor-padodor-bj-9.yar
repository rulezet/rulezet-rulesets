rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67efd38a9d1ed66e80ebf55a95db6fab53d94da2f58e4d0cbf19b7e96d1b8d6a"

  strings:
    $s1 = "o#iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}