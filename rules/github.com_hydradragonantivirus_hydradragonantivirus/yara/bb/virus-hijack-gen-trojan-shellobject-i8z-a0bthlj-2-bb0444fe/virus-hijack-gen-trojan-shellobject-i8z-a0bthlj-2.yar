rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_a0BtHLj_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@a0BtHLj_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3c22461bc36d07578ec1f8b528637938e5352acd4f05f792f733bed6456ee01"

  strings:
    $s1 = "!Error Down" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}