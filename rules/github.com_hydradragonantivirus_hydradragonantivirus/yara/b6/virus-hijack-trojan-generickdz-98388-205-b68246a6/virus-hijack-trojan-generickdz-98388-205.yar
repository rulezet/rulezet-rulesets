rule Virus_Hijack_Trojan_GenericKDZ_98388_205 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_205.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc61ffc24da7a16d349270ef19167cd8c04ae6610ea497d2726b2a1c81a72d70"

  strings:
    $s1 = "qP%HERe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}