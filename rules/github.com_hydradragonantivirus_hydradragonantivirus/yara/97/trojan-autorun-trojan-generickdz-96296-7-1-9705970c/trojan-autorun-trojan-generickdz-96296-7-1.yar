rule Trojan_Autorun_Trojan_GenericKDZ_96296_7_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.96296_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3003b38d6325a32d2e6128b31e359f60a902fb3d06361d3f96d92e3deee76"

  strings:
    $s1 = "e>MotT<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}