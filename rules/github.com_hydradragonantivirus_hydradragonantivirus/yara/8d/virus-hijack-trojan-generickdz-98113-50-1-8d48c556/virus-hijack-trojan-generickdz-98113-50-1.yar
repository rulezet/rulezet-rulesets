rule Virus_Hijack_Trojan_GenericKDZ_98113_50_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_50_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "936a5db9502d482d0c631b8c51604cffc3a52d90a1115105bda8664e55799009"

  strings:
    $s1 = "COof$l" fullword ascii
    $s2 = "0%lOCk}" fullword ascii
    $s3 = ",sOlo*" fullword ascii
    $s4 = "$*VeTo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}