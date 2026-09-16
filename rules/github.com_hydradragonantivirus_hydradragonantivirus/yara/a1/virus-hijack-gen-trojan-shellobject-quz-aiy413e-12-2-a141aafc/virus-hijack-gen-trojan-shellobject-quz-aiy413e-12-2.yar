rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_12_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ceb03ff5a6bfd5f50cfb8291bc07580de9d3f395f47cfaa7eab1093166e9c61"

  strings:
    $s1 = "wELl>]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}