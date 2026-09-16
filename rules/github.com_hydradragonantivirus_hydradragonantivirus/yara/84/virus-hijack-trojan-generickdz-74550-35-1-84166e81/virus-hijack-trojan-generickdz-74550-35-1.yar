rule Virus_Hijack_Trojan_GenericKDZ_74550_35_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c21ef6e406040bd91d7a4f902d2c9750c1330b51759906b002259f4565e73da0"

  strings:
    $s1 = "DN*RoKA" fullword ascii
    $s2 = "[,B[YiLL" fullword ascii
    $s3 = "04`capE;xSh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}