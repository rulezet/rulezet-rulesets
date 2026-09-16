rule Virus_Hijack_Gen_Trojan_ShellObject_yyZ_a8BkLUm_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.yyZ@a8BkLUm_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebfa9be79c4f6869d67f0669755afddd9df1087922b7bc5fb1d04bb2f6e2d4ac"

  strings:
    $s1 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}