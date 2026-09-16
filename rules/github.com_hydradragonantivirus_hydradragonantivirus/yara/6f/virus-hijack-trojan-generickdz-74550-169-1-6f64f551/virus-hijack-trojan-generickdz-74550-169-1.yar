rule Virus_Hijack_Trojan_GenericKDZ_74550_169_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_169_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "427f2a876eb5a45f761f1f3771844426dd133b9480b78eda982bbb79f4c397e3"

  strings:
    $s1 = "DaLT<l$" fullword ascii
    $s2 = "NAtr;n" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}