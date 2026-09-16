rule Trojan_Danger_Trojan_GenericKD_67166905_6_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40203398d3017edc51a4a2985a45ee51cee9839878358ed0dd5b0f5217835d1d"

  strings:
    $s1 = "CSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii
    $s2 = "deLL{i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}