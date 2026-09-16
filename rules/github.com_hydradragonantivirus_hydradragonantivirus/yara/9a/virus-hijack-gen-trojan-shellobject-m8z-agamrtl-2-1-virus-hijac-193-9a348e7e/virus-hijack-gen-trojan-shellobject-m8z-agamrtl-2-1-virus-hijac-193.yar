import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aGAMRTl_2_1_Virus_Hijac_193 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGAMRTl_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGAMRTl_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29d710c4a1fb3d78c8727b981131b8a9883700c266d16bb4a4d17892dd47d8b6"
    hash2       = "5d6fbe551fe95c4108ca41e507f27be4f304ba70a2b2326f96d3ba9541f88a22"

  strings:
    $s1 = "  Attempting connection" fullword ascii
    $s2 = "Procedure not found in library HHCtrl.ocx: HtmlHelpA" fullword ascii
    $s3 = "Library not found: HHCtrl.ocx" fullword ascii
    $s4 = "ctl::AggregableComInspectableObject<T>::CreateInstance(pOuter,&pNewInstance)" fullword wide
    $s5 = "  Creating packet receiver" fullword ascii
    $s6 = "DVD Talk Features" fullword ascii
    $s7 = "About Us: CLICK" fullword ascii
    $s8 = "  Creating packet sender" fullword ascii
    $s9 = "CheckEgress returned  %x " fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "e1962136d28298fbdc410ff2954bca35" and (all of them)
    ) or (all of them)
}