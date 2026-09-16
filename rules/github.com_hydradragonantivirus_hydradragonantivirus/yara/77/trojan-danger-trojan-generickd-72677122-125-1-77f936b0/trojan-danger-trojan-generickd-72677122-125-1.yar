rule Trojan_Danger_Trojan_GenericKD_72677122_125_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_125_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67b8416601169673bb4c3ae0c553b912ccb8e897180b390e20dcc37570e64c8d"

  strings:
    $s1 = "ation error" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}