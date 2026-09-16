rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_64_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_64_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a427b8bdda851a672ca1bfcd5508619ad56d72f68f0193651ab641957e7e5d9"

  strings:
    $s1 = "FVhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}