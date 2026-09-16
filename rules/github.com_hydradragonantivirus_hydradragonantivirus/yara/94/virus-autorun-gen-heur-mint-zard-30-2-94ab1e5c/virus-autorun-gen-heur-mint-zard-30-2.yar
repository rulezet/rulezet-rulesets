rule Virus_Autorun_Gen_Heur_Mint_Zard_30_2 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Gen.Heur.Mint.Zard.30_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7f2be52a0a52f55181ddf60679cf5e7b12cd2fe855efe1903901cdd09bb40eb"

  strings:
    $s1 = "Order Management User: is defined as an individual authorized by you to use the applicable licensed applica0r4hMZCrkn0r4hMZCrkn0" ascii
    $s2 = "Order Management User: is defined as an individual authorized by you to use the applicable licensed applica0r4hMZCrkn0r4hMZCrkn0" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}