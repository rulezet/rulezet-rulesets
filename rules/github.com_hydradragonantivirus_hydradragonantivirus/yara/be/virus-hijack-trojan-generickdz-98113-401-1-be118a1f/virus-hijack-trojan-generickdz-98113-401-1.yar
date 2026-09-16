rule Virus_Hijack_Trojan_GenericKDZ_98113_401_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_401_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "714b4581037b0c189cd2b91d2299cabc008e5d31b04fcc7e497fc803e91cebf2"

  strings:
    $s1 = "t6*peAK$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}