rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_46_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_46_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87817e877c26687e21d3663dc1d3a7c073f49862982324ee744e93a6aa5961a6"

  strings:
    $s1 = "_debug': False, " fullword ascii
    $s2 = "e, 'x_seq': None, 'f_seq': None,0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}