rule Virus_Hijack_Gen_Heur_Mint_Zard_30_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.Zard.30_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e8487c403c86918518317ed7e4d9d33b895d5c596cf428e2668ed2f4794d66d"

  strings:
    $s1 = "Fand C" fullword ascii
    $s2 = "aseM*x" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}