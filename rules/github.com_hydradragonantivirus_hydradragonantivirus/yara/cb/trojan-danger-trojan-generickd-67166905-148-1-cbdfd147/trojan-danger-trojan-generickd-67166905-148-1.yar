rule Trojan_Danger_Trojan_GenericKD_67166905_148_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_148_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58bfeb78634f5c3ea8b7a0625bdbb41675fb83365eed44082ff3dd1d77f16179"

  strings:
    $s1 = ":University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}