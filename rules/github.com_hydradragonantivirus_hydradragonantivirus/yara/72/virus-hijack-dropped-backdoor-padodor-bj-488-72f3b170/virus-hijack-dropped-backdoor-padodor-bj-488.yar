rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_488 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_488.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d12eb5374c852446478f8d6322a0ff4b106da2b49ed4aa9a5a3e5945d38dcba7"

  strings:
    $s1 = "weiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}