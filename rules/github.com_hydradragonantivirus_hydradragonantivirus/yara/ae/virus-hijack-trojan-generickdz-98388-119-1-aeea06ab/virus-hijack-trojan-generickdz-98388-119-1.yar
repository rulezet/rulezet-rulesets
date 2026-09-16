rule Virus_Hijack_Trojan_GenericKDZ_98388_119_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_119_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a2a2cc8476ba21d43882834e0bf8c548e380d90b63c802d76e74f1f0dd34db6"

  strings:
    $s1 = "Q%pACk[bZ]9Fj" fullword ascii
    $s2 = "ShAm<y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}