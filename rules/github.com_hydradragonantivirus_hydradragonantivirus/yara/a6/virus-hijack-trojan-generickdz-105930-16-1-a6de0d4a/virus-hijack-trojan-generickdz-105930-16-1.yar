rule Virus_Hijack_Trojan_GenericKDZ_105930_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c18aae30f05e78b6e3af62ab76587037908b4bc5fa4510ff23839183bb0dcbd6"

  strings:
    $s1 = "}cOIr)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}