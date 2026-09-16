rule Virus_Hijack_Gen_Heur_Mint_Zard_30_31 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.Zard.30_31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "015c6ad9381ef5c7c586636b0a38f9c6162596db8337545d7314117ea6742215"

  strings:
    $s1 = "t+ IntegratX with SO(" fullword ascii
    $s2 = "Termin*b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}