rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_30_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "564fb8db11dd2876848d7630a0ad72091dd9791effb0b2eac2b566fa745ddd44"

  strings:
    $s1 = "qhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}