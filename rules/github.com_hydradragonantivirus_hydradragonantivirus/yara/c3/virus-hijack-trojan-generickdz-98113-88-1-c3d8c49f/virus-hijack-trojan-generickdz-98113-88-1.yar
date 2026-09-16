rule Virus_Hijack_Trojan_GenericKDZ_98113_88_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_88_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a90428e49379c909bd10d4ef1d4ade0c57fdf80b83459005c984af8d140d6f6"

  strings:
    $s1 = "PAwK}_7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}