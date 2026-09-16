rule Virus_Hijack_Trojan_GenericKDZ_98388_96_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_96_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81d444c0aa5a095653e0dbc155987f5907c1e15636e919865f24febee476139a"

  strings:
    $s1 = "+5]KILP`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}