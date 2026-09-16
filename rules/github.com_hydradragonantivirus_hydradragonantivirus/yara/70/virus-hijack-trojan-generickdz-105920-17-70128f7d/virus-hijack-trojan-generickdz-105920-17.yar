rule Virus_Hijack_Trojan_GenericKDZ_105920_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105920_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1036dde912e75805e61c6e8c6097f39466fb9c6b6a426edfc0526ac5a6320809"

  strings:
    $s1 = "T*GIRl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}