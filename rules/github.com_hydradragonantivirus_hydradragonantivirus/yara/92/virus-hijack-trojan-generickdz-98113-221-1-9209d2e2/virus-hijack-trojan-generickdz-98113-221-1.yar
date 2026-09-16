rule Virus_Hijack_Trojan_GenericKDZ_98113_221_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_221_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99819b5aefd54f4628a221258c94d8ee509c6019f8ce6f08d241ce1e10e517c1"

  strings:
    $s1 = "@CHub}dt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}