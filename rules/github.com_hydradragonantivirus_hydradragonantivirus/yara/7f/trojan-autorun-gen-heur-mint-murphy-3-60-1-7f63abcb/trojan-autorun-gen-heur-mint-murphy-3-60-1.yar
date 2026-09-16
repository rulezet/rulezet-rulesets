rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_60_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_60_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd1a330a89a7d16305c48dde9c70006c4d59429bc9296463beab4696b3114826"

  strings:
    $s1 = "e^functionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}