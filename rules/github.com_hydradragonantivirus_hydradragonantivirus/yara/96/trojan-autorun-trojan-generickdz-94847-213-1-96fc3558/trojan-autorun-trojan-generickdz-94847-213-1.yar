rule Trojan_Autorun_Trojan_GenericKDZ_94847_213_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_213_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab57151eb79aa25335e19678c7513a15d1b9ffa00dd4a3fbc79fb3211b25e92d"

  strings:
    $s1 = "[orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}