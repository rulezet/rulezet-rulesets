import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_200_2_Tro_29 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_200_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_20_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "109d560d0a9e215237dfc637ecb70c537cf054318a442e0eb996d52dc5cc046c"
    hash2       = "3efae6d9138b37077dde2df5362fde7345b3c7cd8a3dd472fbc8e26406b73293"

  strings:
    $s1  = "Root ,I" fullword ascii
    $s2  = "System ,I" fullword ascii
    $s3  = "System@iH" fullword ascii
    $s4  = "Owner ,I" fullword ascii
    $s5  = "Count(aG" fullword ascii
    $s6  = "Position ,I" fullword ascii
    $s7  = "Count`pG" fullword ascii
    $s8  = "Monochrome$" fullword ascii
    $s9  = "Count@7I" fullword ascii
    $s10 = "Count uI" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f9e81afd2870aaecd8ace36b2893b1d3" and (all of them)
    ) or (all of them)
}