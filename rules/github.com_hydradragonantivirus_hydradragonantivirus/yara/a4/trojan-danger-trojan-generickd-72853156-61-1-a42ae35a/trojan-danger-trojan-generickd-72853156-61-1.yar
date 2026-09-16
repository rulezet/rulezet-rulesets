rule Trojan_Danger_Trojan_GenericKD_72853156_61_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_61_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b640fa71bb7a59b4cfde4e70a498ccf5e9151d4949db84f457db1bc6772e85f5"

  strings:
    $s1 = "Clock Microsoft " fullword wide
    $s2 = "Clock " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}