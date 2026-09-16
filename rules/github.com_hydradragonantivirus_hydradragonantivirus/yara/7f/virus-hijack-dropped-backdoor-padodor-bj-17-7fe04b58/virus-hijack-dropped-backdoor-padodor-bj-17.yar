rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c47ddec6cf443a505943d35863614db3f8c1578847322af1f23e2d566d62e2c2"

  strings:
    $s1 = "ciLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}