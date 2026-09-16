rule Trojan_Autorun_Trojan_GenericKDZ_94847_114_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_114_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "231695501510681f416667141f2bf15ce1d0ec6273b9954382e621ff0549b8ef"

  strings:
    $s1 = "=OUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}