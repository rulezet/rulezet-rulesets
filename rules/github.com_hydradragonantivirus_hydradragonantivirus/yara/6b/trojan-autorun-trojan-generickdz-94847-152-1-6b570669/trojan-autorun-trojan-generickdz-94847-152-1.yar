rule Trojan_Autorun_Trojan_GenericKDZ_94847_152_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_152_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fc6e283fec2084e0eca0801ca3385fec37d24abb40c6c5133898c381f766eb7"

  strings:
    $s1 = "G&authorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii
    $s2 = "Applications National Language Support (NLS) Supplement CD Packs:`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}