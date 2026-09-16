rule Virus_Hijack_Gen_Heur_Mint_Zard_30_24_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.Zard.30_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29885f2e23c853b51903b7e43cf7bb5d01a3eafe2cd2303bfb04f2f439169dfe"

  strings:
    $s1 = "}>Module" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}