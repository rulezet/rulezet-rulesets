rule Virus_Hijack_Trojan_GenericKDZ_98388_191_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_191_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fd76e1810eda47de3a97b75fa1064f76d56d0082ee27be52afe6be481488d7e"

  strings:
    $s1 = "NAwt}%" fullword ascii
    $s2 = "\"N8[RAYa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}