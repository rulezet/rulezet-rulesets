rule Virus_Hijack_Gen_Heur_Mint_Zard_30_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.Zard.30_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95659c9d54bc6abfc933a6a1874c2213fb7881e9f83ab21f6c3eb645af41f08a"

  strings:
    $s1 = "Fand C" fullword ascii
    $s2 = "aseM*x" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}