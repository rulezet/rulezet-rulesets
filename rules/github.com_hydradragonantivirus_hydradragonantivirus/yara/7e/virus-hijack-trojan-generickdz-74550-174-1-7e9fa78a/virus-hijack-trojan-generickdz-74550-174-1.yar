rule Virus_Hijack_Trojan_GenericKDZ_74550_174_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_174_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c020cd3b5435819d9ffc2f60bc99c659bf3f9fb8bc2d50c2d71726d965a594b3"

  strings:
    $s1 = "}%sOOL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}