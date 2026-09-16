rule Trojan_Danger_Trojan_GenericKD_67166905_340_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_340_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f27b1cf188d6026426a202747a89cd3da941a3b76d512bbc2c0fdfc6be347bfd"

  strings:
    $s1 = ">dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}