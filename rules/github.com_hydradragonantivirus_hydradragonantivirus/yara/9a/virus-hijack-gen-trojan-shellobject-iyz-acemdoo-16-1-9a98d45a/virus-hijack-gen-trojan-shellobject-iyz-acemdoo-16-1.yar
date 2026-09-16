rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f12f621e3d7dc56e7c9afeb92b00d2857fd65c40847edd7162b1e78a60230a5e"

  strings:
    $s1 = "vIse,VJG" fullword ascii
    $s2 = "FROM Win32_NetworkAdapter " fullword wide
    $s3 = "SELECT MACAddress " fullword wide
    $s4 = "((MACAddress Is Not NULL) " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}