rule Virus_Hijack_Gen_Trojan_ShellObject_oyZ_aeWgNZc_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oyZ@aeWgNZc_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3d524b2e652c3bd8cd00d272235e55f40368b26bfb0f19305d795026613d9a2"

  strings:
    $s1 = "0Incorrect number of parameters in function call.'\"ReDim\" used without an array variable.>Illegal text at the end of statement" wide
    $s2 = "opera?" fullword ascii
    $s3 = ":known ex" fullword ascii
    $s4 = "oWideChar)Diva" fullword ascii
    $s5 = "?miss:k7" fullword ascii
    $s6 = ">ds coLp" fullword ascii
    $s7 = "@(amir" fullword ascii
    $s8 = "m)SaIc" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}