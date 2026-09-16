rule Virus_Hijack_Trojan_GenericKDZ_98113_228_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_228_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e2996ed53f058fb64dd8aec876e27176fc9dc707a70f59f39d4484f72da5cba"

  strings:
    $s1 = "heml!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}