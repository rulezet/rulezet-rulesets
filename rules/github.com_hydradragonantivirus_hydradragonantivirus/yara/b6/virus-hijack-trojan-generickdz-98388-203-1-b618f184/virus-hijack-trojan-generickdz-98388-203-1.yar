rule Virus_Hijack_Trojan_GenericKDZ_98388_203_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_203_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "121557d8a059d172ec3c61fb905cf5fc2e025825c794e85525937307a373a6cc"

  strings:
    $s1 = "\\ DOle" fullword ascii
    $s2 = "*DUly." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}