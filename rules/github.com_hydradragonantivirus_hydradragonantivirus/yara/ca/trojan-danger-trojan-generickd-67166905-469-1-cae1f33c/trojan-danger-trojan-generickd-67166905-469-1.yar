rule Trojan_Danger_Trojan_GenericKD_67166905_469_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_469_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fb5d4e54c33fe2b83446910cbf0172ee2c5c82915a5ba1e40f1b8c47d774891"

  strings:
    $s1 = "Eipurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}