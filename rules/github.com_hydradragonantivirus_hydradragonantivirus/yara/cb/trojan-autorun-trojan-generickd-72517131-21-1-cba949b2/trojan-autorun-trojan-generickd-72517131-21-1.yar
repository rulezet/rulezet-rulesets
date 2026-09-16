rule Trojan_Autorun_Trojan_GenericKD_72517131_21_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b010cf18c7d9aaf083821cb5a78edb90ccd117bc11e0cd9d10445153c4c317f1"

  strings:
    $s1 = ">User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}