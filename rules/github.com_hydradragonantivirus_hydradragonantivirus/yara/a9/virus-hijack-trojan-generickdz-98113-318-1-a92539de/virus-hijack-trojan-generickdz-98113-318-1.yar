rule Virus_Hijack_Trojan_GenericKDZ_98113_318_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_318_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28cc2401832e66e8f97fcaa493f3dadc23367190fe2f4b834916d75dc872f8bc"

  strings:
    $s1 = "+:sIKa{f" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}