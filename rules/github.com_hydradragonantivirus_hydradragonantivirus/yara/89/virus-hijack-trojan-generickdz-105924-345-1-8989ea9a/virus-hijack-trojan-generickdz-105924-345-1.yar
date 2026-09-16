rule Virus_Hijack_Trojan_GenericKDZ_105924_345_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_345_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bff592dbb48d483e2cab89a347fd101a7112c27efd5ff6a1ee68b46da9165408"

  strings:
    $s1 = "burn]-M" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}