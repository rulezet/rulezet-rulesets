rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_255 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_255.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91acac53df2dfd51b692d90d2b9a044272d9a8a4bb7968a979ce83c2f85c94cd"

  strings:
    $s1 = "`8iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}