rule Virus_Hijack_Gen_Trojan_ShellObject_p8Z_aO1tmfb_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8Z@aO1tmfb_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "285ce284a7d8ff1ece3efae3b6e818f456c611644ed738a20b44bde9d5365a16"

  strings:
    $s1 = "c:\\users\\masterhyp\\documents\\visual studio 2012\\Projects\\WindowsApplication5\\WindowsApplication5\\obj\\Debug\\WindowsAppl" ascii
    $s2 = "c:\\users\\masterhyp\\documents\\visual studio 2012\\Projects\\WindowsApplication5\\WindowsApplication5\\obj\\Debug\\WindowsAppl" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}