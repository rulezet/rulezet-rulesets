rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86925d129f07b4628b04e945366bf2ce0a2020d9210730f8066e711434336b05"

  strings:
    $s1 = "edit box" fullword ascii
    $s2 = "Type something here" fullword ascii
    $s3 = "RegistryDemo MFC Application" fullword wide
    $s4 = "RegistryDemo Application" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}