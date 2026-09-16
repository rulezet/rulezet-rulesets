rule Trojan_Autorun_Trojan_GenericKD_72517131_156_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_156_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c97789149687c7219db4aa218f9e294684457e8fa6c22772c6ad9dcc402f8ec"

  strings:
    $s1 = "(User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}