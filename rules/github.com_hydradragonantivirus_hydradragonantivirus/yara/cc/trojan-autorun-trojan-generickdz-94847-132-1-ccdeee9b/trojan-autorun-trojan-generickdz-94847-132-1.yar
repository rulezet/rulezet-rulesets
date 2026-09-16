rule Trojan_Autorun_Trojan_GenericKDZ_94847_132_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_132_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "372a2187b7602ab2ac80e4b8c4c32f48d8c34b7335d61c9d7eeb113fa6f30c68"

  strings:
    $s1 = "Limited, East Point Business Park, Fairview, Dublin 3, Ireland," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}