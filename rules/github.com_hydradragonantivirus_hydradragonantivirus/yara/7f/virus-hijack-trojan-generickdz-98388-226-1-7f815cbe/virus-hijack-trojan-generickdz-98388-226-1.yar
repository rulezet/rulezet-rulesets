rule Virus_Hijack_Trojan_GenericKDZ_98388_226_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_226_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fff3f153ac1cbe35f450047ad1264c9c7e23e82003db4602b3b6540fb96e6a99"

  strings:
    $s1 = "peCK%O" fullword ascii
    $s2 = "'\"alan" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}