rule Trojan_Autorun_Trojan_GenericKDZ_72348_8_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.72348_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e197faeace16a2a48123d82c671e1f5829ac53bc8d348c61b61ea9b09c4e4b5"

  strings:
    $s1 = "BLIP#C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}