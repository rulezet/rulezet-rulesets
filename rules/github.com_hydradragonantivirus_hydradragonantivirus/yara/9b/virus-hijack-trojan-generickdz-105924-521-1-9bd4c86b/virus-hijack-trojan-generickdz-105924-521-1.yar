rule Virus_Hijack_Trojan_GenericKDZ_105924_521_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_521_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "857de03411e7e10e3d58e4c5fe8d6941ade5184f1adea77d2934ff461ecfae73"

  strings:
    $s1 = "%cKZ:HatE>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}