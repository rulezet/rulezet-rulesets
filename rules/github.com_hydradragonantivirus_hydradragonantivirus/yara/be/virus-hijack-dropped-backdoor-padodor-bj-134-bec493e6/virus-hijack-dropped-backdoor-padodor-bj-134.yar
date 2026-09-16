rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_134 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_134.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a27c09c8e4ec9c50fb9ac993e11e19ea86822553e9040d82ad5b054da3252ad"

  strings:
    $s1 = "LiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}