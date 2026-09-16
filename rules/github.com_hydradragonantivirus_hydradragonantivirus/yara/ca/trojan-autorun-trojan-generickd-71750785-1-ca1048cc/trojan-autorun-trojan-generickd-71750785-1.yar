rule Trojan_Autorun_Trojan_GenericKD_71750785_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.71750785_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "755b0448569a97226d0ff72780485a407db7cb6e81193847876ab2d3fe063e12"

  strings:
    $s1 = "_lor service that is subject to a discount or a pr" fullword ascii
    $s2 = "GAUt>-9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}