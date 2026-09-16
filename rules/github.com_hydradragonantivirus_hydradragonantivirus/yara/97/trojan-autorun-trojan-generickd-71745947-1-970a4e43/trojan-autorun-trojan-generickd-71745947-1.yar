rule Trojan_Autorun_Trojan_GenericKD_71745947_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.71745947_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acb73220c0c9e7c61d95cf14903e817be116b00b6b1f7191292f5acfa75d2836"

  strings:
    $s1 = "$User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}