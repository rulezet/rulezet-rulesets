rule Virus_Hijack_Trojan_GenericKDZ_98113_371_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_371_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62ff4cff51fa2604aa85421f843364631d84e178a4943c6ec7167196ab990b9c"

  strings:
    $s1 = "w*KoRE" fullword ascii
    $s2 = "E*AGon" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}