rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_26_2_Virus_Hijac_299 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_26_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_27_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_28_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_29_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_30_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcde34a947b71384d21f0fdc7ec5e5e8a9296bb3cdd34b83a5e1b5120cd93508"
    hash2       = "e38e22adb7d11b38550a42d9c05814285c2dbfb4815e5dfea8951396ca86c45d"
    hash3       = "ca7f3f84233d81860c1f6250951587cb7fe8c5bdbf72e6f8452bd3470a0586bb"
    hash4       = "8948fb6e75689cf9670fe846352643c89544252291348a535e427d778cb5897c"
    hash5       = "4695f3308e2e124c6a4fd8dbaae803852a5c840c139b5e678286cb6d72405634"
    hash6       = "eee1d31a59a1e8d5d1fc216dfc32e0231c3b2e15c23e1747da23c096188d7782"

  strings:
    $s1  = "It Is Difficult to get Html to show all 255 ASCII Characters, So Other Text Is Needed To Fix This Problem. " fullword ascii
    $s2  = "[Html Colour ASCII]" fullword ascii
    $s3  = "Manual Control:" fullword ascii
    $s4  = "Use All 255 ASCII Characters." fullword ascii
    $s5  = "Open Html File After Creation?" fullword ascii
    $s6  = "Horizontal Detail:" fullword ascii
    $s7  = "Create And Write Html Ascii To File" fullword ascii
    $s8  = "Start (Html)" fullword ascii
    $s9  = "Clear Ascii Image" fullword ascii
    $s10 = "Use Blue Values" fullword ascii
    $s11 = "[1) Resize Image]" fullword ascii
    $s12 = "Start (Auto)" fullword ascii
    $s13 = "Sample (Faster)" fullword ascii
    $s14 = "[3) Draw Ascii Image]" fullword ascii
    $s15 = "Draw Ascii Image" fullword ascii
    $s16 = "Image To ASCII Art, By Arvinder Sehmi" fullword ascii
    $s17 = "Only Use 4 ASCII Characters." fullword ascii
    $s18 = "Use Green Values" fullword ascii
    $s19 = "[Line Art Options]" fullword ascii
    $s20 = "Step 3: Create The ASCII Art." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}