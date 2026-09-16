rule Virus_Hijack_Gen_Heur_Mint_Zard_30_23_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.Zard.30_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bd6320de8ef5aed64cff55247d94254d0f0c3700408717f21cc029a1750006e"

  strings:
    $s1 = "  <description>sponde</description> " fullword ascii
    $s2 = "ammonic" fullword ascii
    $s3 = "Queasiness" fullword ascii
    $s4 = "tinte file pista" fullword wide
    $s5 = "Help*8?nno" fullword ascii
    $s6 = ":Blocky" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}