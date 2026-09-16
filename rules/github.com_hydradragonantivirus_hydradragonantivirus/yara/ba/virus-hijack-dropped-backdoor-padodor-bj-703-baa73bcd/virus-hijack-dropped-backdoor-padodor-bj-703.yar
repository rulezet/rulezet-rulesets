rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_703 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_703.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04ec64edc71c70d61117441c866bdcbed649d6d6dc14b93bd281620d9790fc63"

  strings:
    $s1 = "+iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}