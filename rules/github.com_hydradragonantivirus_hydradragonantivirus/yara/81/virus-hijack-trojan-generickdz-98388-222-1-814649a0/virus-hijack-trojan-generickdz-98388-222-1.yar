rule Virus_Hijack_Trojan_GenericKDZ_98388_222_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_222_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b457a9696bad843de3e694a15e1227d292d422921aeb230839b2a93e01130973"

  strings:
    $s1 = "_}NaWT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}