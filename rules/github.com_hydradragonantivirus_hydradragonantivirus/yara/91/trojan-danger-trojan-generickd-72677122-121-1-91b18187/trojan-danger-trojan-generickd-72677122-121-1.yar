rule Trojan_Danger_Trojan_GenericKD_72677122_121_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_121_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e422c8a6cea77ea5cd7cab63599883e3a705746a8e7c551bd41b5811c11d883"

  strings:
    $s1 = "Hall&[5$" fullword ascii
    $s2 = "Themida Security" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}