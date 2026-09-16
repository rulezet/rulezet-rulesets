rule Virus_Hijack_Gen_Trojan_ShellObject_GyZ_am0pOwg_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.GyZ@am0pOwg_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "046e029c41ac8987649a05e98db75a462e6d42f5f32e871f907036d23ec2d701"

  strings:
    $s1 = "lete Obj" fullword ascii
    $s2 = "li} has made a.tC" fullword ascii
    $s3 = ". ??e{flat}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}