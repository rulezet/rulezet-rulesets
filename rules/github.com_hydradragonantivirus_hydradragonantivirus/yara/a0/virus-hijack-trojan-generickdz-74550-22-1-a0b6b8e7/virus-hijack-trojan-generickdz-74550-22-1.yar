rule Virus_Hijack_Trojan_GenericKDZ_74550_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1e9c07c30d9665723eb6809e18260e61f315576b7ac5c068c21ce98d9494b39"

  strings:
    $s1 = "4:}tODE." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}