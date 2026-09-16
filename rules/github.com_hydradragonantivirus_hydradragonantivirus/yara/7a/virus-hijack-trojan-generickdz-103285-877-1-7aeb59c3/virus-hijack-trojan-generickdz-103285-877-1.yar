rule Virus_Hijack_Trojan_GenericKDZ_103285_877_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_877_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c99cc8b34524015badda5483270c956b2c287fe4c527385d6775bd15cdd29e3e"

  strings:
    $s1 = "hmProxy!= NULL" fullword ascii
    $s2 = "Can't load library from memory." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}