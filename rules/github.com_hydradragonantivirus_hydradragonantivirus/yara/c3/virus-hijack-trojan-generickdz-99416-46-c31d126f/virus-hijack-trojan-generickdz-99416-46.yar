rule Virus_Hijack_Trojan_GenericKDZ_99416_46 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_46.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "981f5735d08bd612817def93ccbcc2fe639d58d61e00421e52f9dbf3ea6c1665"

  strings:
    $s1 = "W{User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}