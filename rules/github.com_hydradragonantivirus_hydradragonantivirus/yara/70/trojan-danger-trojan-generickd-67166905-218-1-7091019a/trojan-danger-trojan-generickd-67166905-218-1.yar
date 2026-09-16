rule Trojan_Danger_Trojan_GenericKD_67166905_218_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_218_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4db32d8405d64c26f0fa3d4a43fb36a9599b60ac1c86543919abcb8bf2c0d57b"

  strings:
    $s1 = "J(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = "J(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}