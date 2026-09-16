rule Trojan_Danger_Trojan_Generic_36486627_11_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Generic.36486627_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ba8e2a630e1a5e058bb36c110b29ddcb520f6e97da3bcef4008c283e761b2a9"

  strings:
    $s1 = "oUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}