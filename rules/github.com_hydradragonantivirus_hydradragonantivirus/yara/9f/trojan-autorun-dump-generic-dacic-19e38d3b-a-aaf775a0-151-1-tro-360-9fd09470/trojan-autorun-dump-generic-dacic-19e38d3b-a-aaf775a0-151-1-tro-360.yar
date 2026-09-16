import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_151_1_Tro_360 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_151_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_152_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_205_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_283_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_284_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_460_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_513_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_554_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_556_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_558_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_573_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@ayMBdto.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@ayMBdto_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@ayMBdto_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@ayMBdto_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@ayMBdto_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@ayMBdto_5.vir, Virus.Hijack_Trojan.GenericKDZ.98388_106.vir, Virus.Hijack_Trojan.GenericKDZ.98388_161.vir, Virus.Hijack_Trojan.GenericKDZ.98388_199.vir, Virus.Hijack_Trojan.GenericKDZ.98388_242.vir, Virus.Hijack_Trojan.GenericKDZ.98388_40.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f400be5fbd3f28b30e46f3830ba1436372f611aab0e3b6a413f5694c7c54db99"
    hash2       = "fff84ec155cee505f67debb744a61f76ae71bd3d1a5a60e1c32e4b9d657d461c"
    hash3       = "612935cf6b3abc62df917d055e5eb4546aaf6ae4c69027923a108b2c5f4a88ed"
    hash4       = "e440e5cf08c433da57dac44ccf14791632c3827e2237b6fe9bae05206ee6604c"
    hash5       = "9c3e253c9056522d7ee6f5d6e32f2247e789cedaed6cf59ec0b308087fbaba54"
    hash6       = "73f348d642a88e6a6224d3e11cab7dd0cac7cacc17eace26f8e841df83025a7f"
    hash7       = "3010909ca12a2d794b90aa134c74f3abdbb4314952e235a936fa62c0daa56909"
    hash8       = "7255667cf9cc7e92f3c1a62ff8624e273fb8a900f6a88b8e45343b249658a143"
    hash9       = "a6b3c1ca187e8ed1a6328b0f1b6bf6af913cfac595628827db645901646f8cdb"
    hash10      = "c7f08828005765d67eef23d4f9cda3ba4da7864f6c9e377ff18c6fa000f4eede"
    hash11      = "db8653a33aa34b1a336501b92b344ac6168a75d54c207e0ebbe470aacd7aa9b2"
    hash12      = "e717d163d8f384d6833be18399a99aa54102f708aa78f2febc728392e96912ca"
    hash13      = "9fbb92a19984d25f2e4882209d6ba9e5cbf3c8574b66003efaad94c5f3ef0a17"
    hash14      = "f79b7b1360d3e757b6d163e504b0699dd5c6a72ca74b1279bb5ce1aecf4e22c0"
    hash15      = "71cf569ffe346ab99026846c23f5008bee56afa07cefe10e3026f0a497d425a5"
    hash16      = "8a8163a67a7526ac8c35f1187fdc6be92fb177ecfb677b93a9f3c05a399361b9"
    hash17      = "de19d97fc16e3326b89b4a3780bcc0a7789688b0e6e2eacd854c6cddf8164f0e"
    hash18      = "38b8fcb28923524f1e65eff4505832e1d088b93a2c428cb74cb8bbdd423515a9"
    hash19      = "358fba9af070577b583044d673b36d79a9c6e6172cd4769b0ea8778f777cfbd4"
    hash20      = "86f935a02337af523d799a2c104034dda7a5db39e507d707c07cd11dce0f0da9"
    hash21      = "9a540728e4134f68ce5d394f28f828a4642ab5c537c0b8bf289b86d18f1f579a"
    hash22      = "e6c4c4677d28e9c81e7574659b8ed0e9c566fc4a5060353218fb464e42513bb8"

  strings:
    $s1 = "Getting Started.one" fullword ascii
    $s2 = "# You should have received a copy of the CC0 Public Domain Dedi0d" fullword ascii
    $s3 = "open the  f" fullword ascii
    $s4 = "Open Notebook.onetoc2" fullword ascii
    $s5 = "-7visua# To the extent possible under law, the author(s) have dedicated all" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c2a87fabf96470db507b2e6b43bd92eb" and (all of them)
    ) or (all of them)
}