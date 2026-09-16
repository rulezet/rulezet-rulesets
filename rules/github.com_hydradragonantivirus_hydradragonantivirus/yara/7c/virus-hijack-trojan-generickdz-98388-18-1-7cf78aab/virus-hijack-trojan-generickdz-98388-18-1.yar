rule Virus_Hijack_Trojan_GenericKDZ_98388_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd6f26e15ded3c7b74f8a607ce41a57d6be15f56a4fd09fc25d7837c51a40ab2"

  strings:
    $s1 = "]>vErT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}