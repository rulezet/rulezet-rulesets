rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f41b3fa4d5253de75b2c66e20edd14c4c70b676b54aad4ea55a3ff28c81d6040"

  strings:
    $s1 = "MASHy>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}