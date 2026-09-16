import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_39_1_Virus_Hijac_216 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_39_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_40_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_41_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_42_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76e360ea8d5561801ac22e240a89358eff7ca36e78d3145af919e54406704c7d"
    hash2       = "cf262af15cf1bb93dd7a33befc777c07c35d4a7ff5f4154843dd978b1ee1f050"
    hash3       = "026a2f1fe8aa3490431c9865c5985f6df910ae9dbcc6bd14e178f7d693d910d3"
    hash4       = "9a09d27cd9466ae5c0d1dad74ae6048f96bc13ae534d438452111f4b850ac38e"
    hash5       = "c29391d2d555b155e802f2f8f1648eddda69d87630e6e27ac8ce12fed5cdc893"

  strings:
    $s1  = "Path=C:\\ProgramData\\Oracle\\Java\\javapath;C:\\Program Files (x86)\\Intel\\iCLS Client\\;C:\\Program Files\\Intel\\iCLS Client" wide
    $s2  = "Electrostatics" fullword ascii
    $s3  = "Preaggressive" fullword ascii
    $s4  = "Muridism" fullword ascii
    $s5  = "Crevice" fullword ascii
    $s6  = "Demersion" fullword ascii
    $s7  = "Goldbeating" fullword ascii
    $s8  = "Garrulously" fullword ascii
    $s9  = "Unstylish" fullword ascii
    $s10 = "Seminebulous" fullword ascii
    $s11 = ">Goldbeating" fullword ascii
    $s12 = "Eupnea" fullword ascii
    $s13 = "Browed" fullword ascii
    $s14 = "Cauligenous" fullword ascii
    $s15 = "Scratchcarding" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "842d02a07c77652cbe415f23219bb0bb" and (8 of them)
    ) or (all of them)
}