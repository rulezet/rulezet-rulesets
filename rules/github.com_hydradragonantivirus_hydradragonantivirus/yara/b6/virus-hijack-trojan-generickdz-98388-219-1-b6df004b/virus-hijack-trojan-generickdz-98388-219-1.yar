rule Virus_Hijack_Trojan_GenericKDZ_98388_219_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_219_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87b11d69da57d6e04e90ba841eda780789e6b3ccf26eafe094bdba27d754b745"

  strings:
    $s1 = "cLag}>qZ" fullword ascii
    $s2 = "}toOt$" fullword ascii
    $s3 = "HeVI}<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}