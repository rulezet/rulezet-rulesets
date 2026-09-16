rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_24_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc68d061c664cc8b68c5b9b4fea8b427b7bd1c08a2104959c8e6acceecca416"

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