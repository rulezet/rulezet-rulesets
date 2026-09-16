rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97c5bfdcebafc055cf5b8f9ea6c935a40025c40982982faaf7d2c0ab34e5fde0"

  strings:
    $s1 = "G)arEA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}