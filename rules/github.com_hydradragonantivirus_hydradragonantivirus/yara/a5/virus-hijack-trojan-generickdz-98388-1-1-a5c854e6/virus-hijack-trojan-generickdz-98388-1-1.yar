rule Virus_Hijack_Trojan_GenericKDZ_98388_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d12941129efc0aafd826bedb119c2beb4e641e7b61229e3a4da3af83f76a6f63"

  strings:
    $s1 = "i<!chOsEn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}