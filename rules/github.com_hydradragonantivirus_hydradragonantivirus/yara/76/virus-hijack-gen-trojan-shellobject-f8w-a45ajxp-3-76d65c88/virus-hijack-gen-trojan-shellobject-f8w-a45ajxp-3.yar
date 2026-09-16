rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a45ajXp_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a45ajXp_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cefe2143adbc56543cd44bb40ecb24ddcc2cf10a4a36e0ab936127ba62acbb76"

  strings:
    $s1 = "Vprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii
    $s2 = "Vprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}