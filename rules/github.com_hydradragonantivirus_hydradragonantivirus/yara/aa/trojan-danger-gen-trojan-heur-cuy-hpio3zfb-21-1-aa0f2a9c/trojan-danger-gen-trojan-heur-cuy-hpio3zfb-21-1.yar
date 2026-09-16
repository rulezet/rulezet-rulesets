rule Trojan_Danger_Gen_Trojan_Heur_cuY_HPIO3zfb_21_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Trojan.Heur.cuY@HPIO3zfb_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c57179163839e868b295231d4907c8098836366c07c0373dded94086f896c3ab"

  strings:
    $s1 = "?orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}