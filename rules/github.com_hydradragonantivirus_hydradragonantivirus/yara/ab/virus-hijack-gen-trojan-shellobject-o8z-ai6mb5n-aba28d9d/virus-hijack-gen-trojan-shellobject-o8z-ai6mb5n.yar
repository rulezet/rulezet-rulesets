rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_ai6MB5n {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@ai6MB5n.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cfd4d5911f4c945575d7930cfd4d647613bcb38f296b267143b79a2bfbfe7f6"

  strings:
    $s1 = "lAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii
    $s2 = "[%WaGe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}