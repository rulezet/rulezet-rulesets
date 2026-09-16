rule Virus_Hijack_Trojan_GenericKDZ_105924_371_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_371_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0468c5c8d505b8ecc80cad69bb7b6b2f9dc25c7ab15bd519ed9533bd63d0d2d"

  strings:
    $s1 = "jAIl#Q" fullword ascii
    $s2 = "jItI>N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}