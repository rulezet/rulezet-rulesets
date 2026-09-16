rule Virus_Hijack_Trojan_GenericKDZ_98113_299_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_299_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b42ceedd4c1ae85f34c8940bd1de9a5c41903f0e5fad3cee5795b5979e105087"

  strings:
    $s1 = "amX<BaZE" fullword ascii
    $s2 = "Tg?sIST" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}