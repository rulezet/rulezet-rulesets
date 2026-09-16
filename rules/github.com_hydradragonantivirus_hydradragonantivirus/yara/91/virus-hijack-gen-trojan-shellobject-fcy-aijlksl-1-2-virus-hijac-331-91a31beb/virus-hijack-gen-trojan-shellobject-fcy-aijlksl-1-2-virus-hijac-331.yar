rule _Virus_Hijack_Gen_Trojan_ShellObject_fCY_aijlKSl_1_2_Virus_Hijac_331 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_1_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_211_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_229_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4f30b2bcf7684c3566aec9365607f66d43cf9ecbb78496d4f608ae2bb7f04e5"
    hash2       = "8bdbc65ae0a6aadb8fa7c794cdd132edc212aee7be8629710986e62a5e4c7dfe"
    hash3       = "72ac7be72a7dcd60e450126e0d7417a3216d25cb70e13ca09c9be24130fd84fa"

  strings:
    $s1  = "missing value for command '%1'" fullword ascii
    $s2  = "missing 'charset' command" fullword ascii
    $s3  = "missing 'unitwidth' command" fullword ascii
    $s4  = "missing 'res' command" fullword ascii
    $s5  = "'internalname' command requires argument" fullword ascii
    $s6  = "missing 'fonts' command" fullword ascii
    $s7  = "missing 'sizes' command" fullword ascii
    $s8  = "bad argument for 'spacewidth' command" fullword ascii
    $s9  = "unrecognised command '%1' after 'kernpairs' or 'charset' command" fullword ascii
    $s10 = "bad argument for 'slant' command" fullword ascii
    $s11 = "bad 'vert' value" fullword ascii
    $s12 = "bad code '%1' for character '%2'" fullword ascii
    $s13 = "character type '%1' out of range" fullword ascii
    $s14 = "bad width for '%1'" fullword ascii
    $s15 = "bad character type for '%1'" fullword ascii
    $s16 = "unrecognised ligature '%1'" fullword ascii
    $s17 = "bad kern amount '%1'" fullword ascii
    $s18 = "invalid input character code '%1'" fullword ascii
    $s19 = "bad number of fonts '%1'" fullword ascii
    $s20 = "'DESC' is not a valid font file name" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}