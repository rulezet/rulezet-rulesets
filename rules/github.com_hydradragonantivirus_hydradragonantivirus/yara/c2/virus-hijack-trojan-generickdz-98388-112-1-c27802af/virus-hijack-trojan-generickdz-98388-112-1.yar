rule Virus_Hijack_Trojan_GenericKDZ_98388_112_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_112_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c32cf4033081e8129a7b9e1e231016d94c3f6c3c0bc7ece7ab5b85eb2096d55"

  strings:
    $s1 = "z[romP" fullword ascii
    $s2 = "VW}LYRA" fullword ascii
    $s3 = "SuRE`Q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}