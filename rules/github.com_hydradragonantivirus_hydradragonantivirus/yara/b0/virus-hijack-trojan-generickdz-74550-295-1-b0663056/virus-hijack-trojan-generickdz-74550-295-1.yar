rule Virus_Hijack_Trojan_GenericKDZ_74550_295_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_295_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d1e43808610823ba36de9805405a660455924e89fa37178856607b983a85251"

  strings:
    $s1 = "A<DinT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}