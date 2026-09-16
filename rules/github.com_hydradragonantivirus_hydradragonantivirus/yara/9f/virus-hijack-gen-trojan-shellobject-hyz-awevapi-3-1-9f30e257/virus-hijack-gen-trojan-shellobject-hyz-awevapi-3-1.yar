rule Virus_Hijack_Gen_Trojan_ShellObject_hyZ_aWevApi_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.hyZ@aWevApi_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe458df46ee7fb2a6d4aac2e678f28ee69ce12ae77d07a3289da48059e9ba2a5"

  strings:
    $s1  = " Descript" fullword ascii
    $s2  = " static thread g" fullword ascii
    $s3  = " Code Is:%d" fullword ascii
    $s4  = "[] closure" fullword ascii
    $s5  = " Base$A_60" fullword ascii
    $s6  = "Rich`l]" fullword ascii
    $s7  = "mplete Object Lnor" fullword ascii
    $s8  = "virtual dis\"map" fullword ascii
    $s9  = "program cannot be run in DOS mod" fullword ascii
    $s10 = "!This " fullword ascii
    $s11 = "Unh]ledE{" fullword ascii
    $s12 = " Class Hier1y" fullword ascii
    $s13 = "August#ulCJune" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}