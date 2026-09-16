rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_37_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_37_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc1e997156d33333da6a8f87c399c7e7f65684d92b80dd12f70b9d747a33515e"

  strings:
    $s1 = "Hosted Named User: is defined as an individual authorized by " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}