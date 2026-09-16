rule Trojan_Danger_Trojan_GenericKD_72677122_165_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_165_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "661b0ef47c3660f4352cbdb88394f85c7a55e70e8b6c0ca37e3462190b853779"

  strings:
    $s1 = "SUsu})" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}