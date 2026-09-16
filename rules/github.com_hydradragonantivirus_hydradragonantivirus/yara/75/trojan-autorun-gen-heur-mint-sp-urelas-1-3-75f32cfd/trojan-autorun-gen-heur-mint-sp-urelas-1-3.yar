rule Trojan_Autorun_Gen_Heur_Mint_SP_Urelas_1_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.SP.Urelas.1_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b944b6fb97ac7879204041c800879607fca135af8a697d4917d3c333508448c"

  strings:
    $s1 = "Samsung Urban" fullword wide
    $s2 = "Ultead Video" fullword wide
    $s3 = "Jghdfsfd Porker" fullword wide
    $s4 = "Maggo Play" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}