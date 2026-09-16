rule Virus_Hijack_Trojan_GenericKDZ_98113_240_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_240_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b38d74add5327a3a86c3c76e7d9843b43d9a0e409a841b22f383ccd70d52976"

  strings:
    $s1 = ">!*OWLY" fullword ascii
    $s2 = ",lICh<p" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}