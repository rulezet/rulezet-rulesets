rule Virus_Hijack_Trojan_GenericKDZ_74550_237_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_237_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d4b90b48eb30e81134631a9e1d514d46a11ae00c4613365322ccf500698f907"

  strings:
    $s1 = "K)PYKe" fullword ascii
    $s2 = "[[loRA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}