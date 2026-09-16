rule Virus_Hijack_Trojan_GenericKDZ_103285_529 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_529.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2007e0b4e8285147f346c31cbaf965d04fb2e6833db9fe2b86955e9bb37acc83"

  strings:
    $s1 = ".Zavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}