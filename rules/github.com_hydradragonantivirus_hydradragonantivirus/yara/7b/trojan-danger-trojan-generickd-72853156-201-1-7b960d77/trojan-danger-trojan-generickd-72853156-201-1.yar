rule Trojan_Danger_Trojan_GenericKD_72853156_201_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_201_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47083319e36554b6c19313aa48f94e2f01d93f8256f1d3d935e11f98eb41a868"

  strings:
    $s1 = "(lEFt#," fullword ascii
    $s2 = "Waky]P" fullword ascii
    $s3 = "c`WugG>" fullword ascii
    $s4 = "}PulE@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}