rule Virus_Hijack_Gen_Heur_Mint_SP_Dropper_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.SP.Dropper.2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d818febcb4d50bcba5f8956b56e525f591e65a5a7a6ba9a4ea378ef8a208af4"

  strings:
    $s1 = "AutoIt v3 Script : 3, 2, 4, 9" fullword wide
    $s2 = "GYPS?;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}