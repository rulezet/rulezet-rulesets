rule Trojan_Danger_Trojan_GenericKD_72677122_117_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_117_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1edc2e28d49db87273644167d2d8e63b1becdc841b2ccf3a93d772e3832034f0"

  strings:
    $s1 = "Needs Win32!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}