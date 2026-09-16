rule Trojan_Danger_Trojan_GenericKD_72853156_434_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_434_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7ab1e7f44225e4fdd48e5078bcf3d78d637047dc1bdf63207b802c3c137162f"

  strings:
    $s1 = "o>gEgg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}