rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_20_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b903186cdb2ab07f89d1760396f28b5f3ba7ce40136fcf45072f58e1c71d6bf"

  strings:
    $s1 = "edit box" fullword ascii
    $s2 = "Type something here" fullword ascii
    $s3 = "LoWy<_N\\" fullword ascii
    $s4 = "Y#o?whun{" fullword ascii
    $s5 = "RegistryDemo MFC Application" fullword wide
    $s6 = "RegistryDemo Application" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}