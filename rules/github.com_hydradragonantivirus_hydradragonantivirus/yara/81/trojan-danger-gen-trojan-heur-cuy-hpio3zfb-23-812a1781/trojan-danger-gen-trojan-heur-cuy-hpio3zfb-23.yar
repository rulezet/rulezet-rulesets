rule Trojan_Danger_Gen_Trojan_Heur_cuY_HPIO3zfb_23 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Trojan.Heur.cuY@HPIO3zfb_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f531352e1a617a89b5aa3be5fad3481536282dbe142dca46d7fdafbcd049bdc3"

  strings:
    $s1 = "37program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = "37program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}