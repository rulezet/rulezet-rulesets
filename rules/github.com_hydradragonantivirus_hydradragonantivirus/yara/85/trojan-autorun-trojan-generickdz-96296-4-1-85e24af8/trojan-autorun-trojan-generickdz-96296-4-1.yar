rule Trojan_Autorun_Trojan_GenericKDZ_96296_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.96296_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35cb36cbf6d74c76167164ee7c03463f0ecfa4821d4d8ba5591d76725861b9da"

  strings:
    $s1 = "hath*a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}