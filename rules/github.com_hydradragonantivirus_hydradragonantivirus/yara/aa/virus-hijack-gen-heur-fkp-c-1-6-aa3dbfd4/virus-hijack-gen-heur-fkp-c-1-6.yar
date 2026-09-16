rule Virus_Hijack_Gen_Heur_FKP__c__1_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.FKP.!c!.1_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2be791672eb437e6b1e4fbde2d228bb12788999a00053e2ca1d8650ad2cb17bf"

  strings:
    $s1 = "bolimba" fullword wide
    $s2 = "Mummied" fullword wide
    $s3 = "Overmourn" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}