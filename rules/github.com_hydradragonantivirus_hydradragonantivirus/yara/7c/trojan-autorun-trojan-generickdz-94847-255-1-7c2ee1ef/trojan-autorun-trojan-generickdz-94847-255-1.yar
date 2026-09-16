rule Trojan_Autorun_Trojan_GenericKDZ_94847_255_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_255_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eaf32adbc6e6c9ac5eaa70e05109856450f12c7326fbdd0aa34c14f8d05fb5f1"

  strings:
    $s1 = "(whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}