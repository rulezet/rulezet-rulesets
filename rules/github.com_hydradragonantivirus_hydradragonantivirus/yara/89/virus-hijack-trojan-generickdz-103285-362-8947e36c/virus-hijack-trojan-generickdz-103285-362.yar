rule Virus_Hijack_Trojan_GenericKDZ_103285_362 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_362.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df3d41f278d4aafd30bac5d1286e17ed26f307e1eb21891b300d4e8841e3e149"

  strings:
    $s1 = "^What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}