rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_424 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_424.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d9f03b6b50a0a093abd7d471260b4c83ba69bfa94f54e9faac5fad4078ed313"

  strings:
    $s1 = "@HiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}