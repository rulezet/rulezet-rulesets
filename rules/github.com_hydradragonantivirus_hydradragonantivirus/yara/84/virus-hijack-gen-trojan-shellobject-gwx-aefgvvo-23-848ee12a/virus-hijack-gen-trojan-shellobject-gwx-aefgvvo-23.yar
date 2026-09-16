rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "220e960fd0d4f3dc1dc2960d4979c253a4d199d0978be132f7314cc47b69c033"

  strings:
    $s1 = "%shall be counted." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}