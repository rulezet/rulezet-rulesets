rule Trojan_Danger_Trojan_GenericKD_72853156_410 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_410.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "856712df32da82c661641adb7770936df9a32e13e6eb896b58e6f20ee39ca5af"

  strings:
    $s1 = "sTOw*R" fullword ascii
    $s2 = "x)miAn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}