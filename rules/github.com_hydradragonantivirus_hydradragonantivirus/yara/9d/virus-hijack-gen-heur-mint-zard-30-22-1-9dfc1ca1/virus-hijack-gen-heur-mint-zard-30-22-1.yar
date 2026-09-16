rule Virus_Hijack_Gen_Heur_Mint_Zard_30_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.Zard.30_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3f35e90abaf9eaf5d168be98edc1bb6420b7a95cd809821882928994d276222"

  strings:
    $s1 = "?paLP%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}