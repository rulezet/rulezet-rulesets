rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e3b5d6ea9a326acac16b9e05a09f262cd8ab1485000eac746c0f44a1328f6de"

  strings:
    $s1 = "Hatful" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}