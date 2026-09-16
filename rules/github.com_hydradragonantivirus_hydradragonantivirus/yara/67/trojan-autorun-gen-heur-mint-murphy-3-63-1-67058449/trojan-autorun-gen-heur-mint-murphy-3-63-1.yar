rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_63_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_63_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f2cebb997179322d15a305059358e5d9dea789ae1346e1b019d6f945106868e"

  strings:
    $s1 = "&mhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}