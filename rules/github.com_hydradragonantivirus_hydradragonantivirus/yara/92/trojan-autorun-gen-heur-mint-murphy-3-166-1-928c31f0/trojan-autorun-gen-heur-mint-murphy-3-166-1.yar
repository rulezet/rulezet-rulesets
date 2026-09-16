rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_166_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_166_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6110e28740c6ee28134a16d5bd9a4f12e86cb287423560cba4efe89a48e83d9c"

  strings:
    $s1 = "LOuP]SuP]Iq" fullword ascii
    $s2 = "Z^<PLUd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}