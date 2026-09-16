rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_338_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_338_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0120da8d7b24a4c1fd15dab981c72dc6e569f47d85d15db17857f7ac3d3c9ef3"

  strings:
    $s1 = "activation, see microsoft.com/piracy/activation.mspx. If the licensed computer is connected to theK" fullword ascii
    $s2 = "\\you to use the applicable licensed application p" fullword ascii
    $s3 = "B. Applicability of AgreementM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}