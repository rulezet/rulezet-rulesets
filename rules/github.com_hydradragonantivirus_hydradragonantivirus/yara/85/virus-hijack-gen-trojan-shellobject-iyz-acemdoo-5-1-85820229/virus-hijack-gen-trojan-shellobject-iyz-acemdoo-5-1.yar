rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed5bfde6b445f4720dc520bdda711168ddee54966a553bdc76673a44ece4ce8a"

  strings:
    $s1 = "Generic Host Process for Win32 Services " fullword wide
    $s2 = "MkUpdate, Version 1.0" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}