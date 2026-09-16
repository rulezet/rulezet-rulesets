rule Trojan_Danger_Trojan_GenericKD_67166905_305_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_305_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f029763e46d0a8cd5aadcfb49d8ecbff44ed527bf51658d3c355a4736d822bcd"

  strings:
    $s1 = "rvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}