rule Trojan_Danger_Trojan_GenericKD_67166905_234_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_234_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4a37ee35d65ffbb226b54b4695d925888484e655db8dc405842e178acc9bedd"

  strings:
    $s1 = "hUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}