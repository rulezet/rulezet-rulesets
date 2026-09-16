rule Virus_Hooker_Trojan_GenericKD_48560802_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.GenericKD.48560802_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35aaedbf416282b062dc9bdd03fa2a905492c8fef266a1f088f69e0ff2f322c1"

  strings:
    $s1 = "mOrE@N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}