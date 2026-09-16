rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_380 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_380.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fa6444bb647c0ea49f740a71996f7e842402de1445113fa3b3548dd2d7dc07c"

  strings:
    $s1 = "(iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}