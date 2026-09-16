rule Virus_Hijack_Gen_Trojan_ShellObject_r0Z_aKzulAn_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r0Z@aKzulAn_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa4449bc834ea757f51b7d29ede7c04c58bc3b88666138b9ee96e1f6d9d16cff"

  strings:
    $s1 = "#Sist#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}