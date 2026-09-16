rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_28_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d4ed2a1713b5ff0fdd841d88d0add81c107027679b1180aef9693b237bb547e"

  strings:
    $s1 = "Recumbent" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}