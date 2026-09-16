rule Virus_Hijack_Trojan_GenericKDZ_103285_867 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_867.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63717c0705b894380f691e22e93dcffbd37362d4611b007f815316fdad90eef9"

  strings:
    $s1 = "availability of Extended Support and Extended Maintenance Supp" fullword ascii
    $s2 = "may renew your order for an additiona" fullword ascii
    $s3 = "$M in Managed Assets: is defined as one million U.S. dollars (Seven hundred and seventy-two thousand four hundredP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}