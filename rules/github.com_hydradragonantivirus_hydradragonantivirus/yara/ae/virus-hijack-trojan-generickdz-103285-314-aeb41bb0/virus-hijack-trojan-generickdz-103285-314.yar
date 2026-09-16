rule Virus_Hijack_Trojan_GenericKDZ_103285_314 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_314.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc7b97364d73f55e6eafd288dd194b853cea7a4467c2b567a3d10473fcbb3e6d"

  strings:
    $s1 = "kInA)I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}