rule Trojan_Autorun_Trojan_GenericKDZ_94847_15_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79f4055074c2ace5d03cce854e060124a8e0072293ba7e68f9abeaee125a06f9"

  strings:
    $s1 = "vauthorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii
    $s2 = "Ym\\L[wESt}\\F" fullword ascii
    $s3 = "Applications National Language Support (NLS) Supplement CD Packs:`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}