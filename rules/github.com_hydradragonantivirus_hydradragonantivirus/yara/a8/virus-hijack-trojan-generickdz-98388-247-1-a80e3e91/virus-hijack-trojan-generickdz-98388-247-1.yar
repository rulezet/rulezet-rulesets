rule Virus_Hijack_Trojan_GenericKDZ_98388_247_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_247_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dc14e8cb840a1e314f0836a8d37b6a88422eaf52e2ddfb4ba2cb260b1a9fa57"

  strings:
    $s1 = "ghAt$\"" fullword ascii
    $s2 = ":cESS'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}