rule Trojan_Autorun_Gen_Heur_Mint_SP_Urelas_1_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.SP.Urelas.1_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e528b42d6ab8bbb75fde462681de898df6f94b79c8b4c71bb62e77b3d006cf67"

  strings:
    $s1 = "assets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}