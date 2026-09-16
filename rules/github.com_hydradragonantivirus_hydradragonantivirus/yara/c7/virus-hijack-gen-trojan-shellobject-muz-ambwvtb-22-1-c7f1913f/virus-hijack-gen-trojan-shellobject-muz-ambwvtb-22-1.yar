rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7d05b344ea39e65d48f3f02dafab1fd639deae7729e6d1ec56ff9413414f065"

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