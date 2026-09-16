rule Virus_Hijack_Trojan_GenericKDZ_103545_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ddf461a2c76545688b7674c60e4b94925b8b8bb396deb888a4c1d19dfc62b55"

  strings:
    $s1 = "(software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii
    $s2 = "^sYfpB`/~O)d4R6f|D`.~E)dAnG" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}