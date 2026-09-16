rule Virus_Hijack_Trojan_GenericKDZ_105930_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "144e3d4e6287bf3d4a21d14c12451c5d7091827e087159ba66aa44b81803e6e2"

  strings:
    $s1 = "NW\"CHAI" fullword ascii
    $s2 = "-,lUrG" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}