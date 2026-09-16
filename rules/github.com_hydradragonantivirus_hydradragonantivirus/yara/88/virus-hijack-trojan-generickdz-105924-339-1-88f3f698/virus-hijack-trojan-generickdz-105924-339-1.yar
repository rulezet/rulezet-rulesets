rule Virus_Hijack_Trojan_GenericKDZ_105924_339_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_339_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22b3980cef5f28a57614e88beceb0952b0f2f90a65c2be33c519ccac1b1f1d36"

  strings:
    $s1 = "C\"DriB" fullword ascii
    $s2 = "BoTe@u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}