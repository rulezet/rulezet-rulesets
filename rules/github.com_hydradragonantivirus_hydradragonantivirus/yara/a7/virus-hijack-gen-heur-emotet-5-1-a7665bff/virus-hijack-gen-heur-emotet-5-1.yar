rule Virus_Hijack_Gen_Heur_Emotet_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Emotet.5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95e5b57c4b044bec9732bb01c1a8dae0a4c325612b88df75b78008d2d97394d2"

  strings:
    $s1 = "intruding" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}