rule Virus_Hijack_Gen_Heur_FKP__c__1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.FKP.!c!.1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd877adc912a28bac41345339d346f26740ec07372e850be96a7686497b2777e"

  strings:
    $s1 = "Bonelessness" fullword wide
    $s2 = "Rascally" fullword wide
    $s3 = "p[(AXES" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}