rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e83365ec07f534bad69a307399ff55212fc271f0c26adbbfb209c3b2971946c7"

  strings:
    $s1 = "Generic Host Process for Win32 Services " fullword wide
    $s2 = " e,AXES" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}