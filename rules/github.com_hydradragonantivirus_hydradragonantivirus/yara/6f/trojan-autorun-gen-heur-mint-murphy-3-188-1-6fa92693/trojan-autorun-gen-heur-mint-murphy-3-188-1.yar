rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_188_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_188_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8903b923860d80982bb0ff325d511b6592605d185fd54246b7d2f77a578f4be1"

  strings:
    $s1 = "informational links in this agreement. The links containing terms that bind you and`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}