rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_507 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_507.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c5f7e67c96d38b2742c6998c25826a52d8b13fd2982d9b1e3e1ad54370cf753"

  strings:
    $s1 = "HMicrosoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}