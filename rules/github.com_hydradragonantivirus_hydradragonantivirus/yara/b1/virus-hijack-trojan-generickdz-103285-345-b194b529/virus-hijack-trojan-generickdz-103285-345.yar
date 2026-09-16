rule Virus_Hijack_Trojan_GenericKDZ_103285_345 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_345.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b2e4d8133a97edfb69e7d4fb6643186718c31aa108e7675a5eb06d7df561601"

  strings:
    $s1 = "8Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}