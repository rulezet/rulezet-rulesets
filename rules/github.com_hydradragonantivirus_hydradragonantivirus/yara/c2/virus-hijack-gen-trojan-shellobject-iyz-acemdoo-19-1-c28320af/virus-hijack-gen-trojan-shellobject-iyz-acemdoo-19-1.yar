rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86313325205b7195c2c3219a59eb0b87c52a7d5fd0552f8219cf9aa13d8e0775"

  strings:
    $s1 = "GUGU?@" fullword ascii
    $s2 = "wOKe[2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}