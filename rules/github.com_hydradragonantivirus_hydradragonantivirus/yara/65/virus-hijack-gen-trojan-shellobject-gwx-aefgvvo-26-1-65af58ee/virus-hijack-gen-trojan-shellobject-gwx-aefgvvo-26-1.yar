rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_26_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_26_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d58b2a5e3ab08d7524027d1ea74a8801c221719ae8207e35383c66e2c17842d5"

  strings:
    $s1 = "Oblational" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}