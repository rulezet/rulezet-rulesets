rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_23_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "354bc5032ca069118838ef9f644581c96e099464b9f0c1b905d5c6cb6d059572"

  strings:
    $s1 = "CallDll Version 1.0" fullword wide
    $s2 = "<Unknown:%d>" fullword wide
    $s3 = "Filtrate" fullword ascii
    $s4 = "Fabout:blank" fullword ascii
    $s5 = "Typically" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}