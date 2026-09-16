rule Trojan_Danger_Trojan_GenericKD_72597336_10 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72597336_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd8db569997666048f0f11dfc0cc0172a8c1b51e8d4e987fd3e7d92525a39d78"

  strings:
    $s1 = "g]dhai]h" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}