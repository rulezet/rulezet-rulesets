rule Virus_Hijack_Trojan_GenericKDZ_99416_30_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5edeb776e5f637b72287ce1261e5257487d163f8b163ffaf56888ce723e9eab5"

  strings:
    $s1 = "TUKe(?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}