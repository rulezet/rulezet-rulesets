rule Virus_Hijack_Gen_Heur_Mint_Zard_30_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.Zard.30_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f9c89750b2dcba3852388fccff8ac117a676df242fb911f17d0d0da9ef54b81"

  strings:
    $s1 = "n?Crea" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}