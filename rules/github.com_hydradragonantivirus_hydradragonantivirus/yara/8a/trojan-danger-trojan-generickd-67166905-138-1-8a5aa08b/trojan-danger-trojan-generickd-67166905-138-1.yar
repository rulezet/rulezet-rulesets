rule Trojan_Danger_Trojan_GenericKD_67166905_138_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_138_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b8cf6cb331b00030c0b52b16a30c19bad6b9235dfc0c33577b61e407877a7ab"

  strings:
    $s1 = "purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}