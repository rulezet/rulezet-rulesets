rule Trojan_Autorun_Trojan_GenericKD_72517131_174_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_174_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e1f553a08064e0d742d3b2eab9d09e0ec4c4254f809b9585c38d5bc18ab3c10"

  strings:
    $s1 = "]User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}