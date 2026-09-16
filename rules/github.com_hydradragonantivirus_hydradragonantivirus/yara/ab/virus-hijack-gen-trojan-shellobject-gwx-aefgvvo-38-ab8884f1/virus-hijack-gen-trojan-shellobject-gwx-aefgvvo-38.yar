rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_38 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_38.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5a49bf234d5468a82b183fe238e3df3691db9da773b33228c02331e4d6eff4e"

  strings:
    $s1 = "Septillion" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}