rule Virus_Hijack_Trojan_GenericKDZ_98113_101_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_101_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e934c4aadca87fa4298794165392ac4919046e300d63f9bb54e4c65ee41818d1"

  strings:
    $s1 = "AMBo(*x" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}