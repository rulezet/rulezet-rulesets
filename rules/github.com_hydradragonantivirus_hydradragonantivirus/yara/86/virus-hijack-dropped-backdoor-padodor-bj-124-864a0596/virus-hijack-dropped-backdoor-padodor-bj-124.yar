rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_124 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_124.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd0cf533f4ee90fd575e71aa2c6aff814c3ec43c4f9454709c635bf56ca0f7f8"

  strings:
    $s1 = "RiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}