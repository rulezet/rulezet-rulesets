rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_743 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_743.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "812281759fcc219f97cab53e84c3ec3bbb2a86e6fa82c4797472869f50f42900"

  strings:
    $s1 = "LQiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}