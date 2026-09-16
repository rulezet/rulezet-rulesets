rule Virus_Hijack_Trojan_GenericKD_36668029 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKD.36668029.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6d7d998274d442873bbb47baba718fff97684c5b15e2e2ce1371b18a308ecda"

  strings:
    $s1 = "Clock Microsoft " fullword wide
    $s2 = "Clock " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}