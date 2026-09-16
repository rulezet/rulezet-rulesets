rule Virus_Hijack_Trojan_GenericKDZ_98113_281 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_281.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dac183cd6e2a234b65bad2e85973891f1f93b462905fe4d88f81b7b229198eb"

  strings:
    $s1 = "@zor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}