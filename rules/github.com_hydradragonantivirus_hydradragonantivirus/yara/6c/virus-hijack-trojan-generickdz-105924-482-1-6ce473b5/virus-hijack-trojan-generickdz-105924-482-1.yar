rule Virus_Hijack_Trojan_GenericKDZ_105924_482_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_482_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ec703c51e450ca54627254a62107245c20218007670d93bdce7300d5d8f6479"

  strings:
    $s1 = "mAst@mt" fullword ascii
    $s2 = "G}u-HMK8}vOlt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}