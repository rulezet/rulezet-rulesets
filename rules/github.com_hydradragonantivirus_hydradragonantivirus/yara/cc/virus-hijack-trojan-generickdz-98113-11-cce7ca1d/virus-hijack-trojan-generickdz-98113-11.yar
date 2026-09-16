rule Virus_Hijack_Trojan_GenericKDZ_98113_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88c35c6f31574afa73c69bd864fb73dda6d3c680a526e08f5129d84d4bcd5f4a"

  strings:
    $s1 = "heNt$tN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}