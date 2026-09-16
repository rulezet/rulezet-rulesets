rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "343f995cc4bcfe7e7df268c37285237269064312ad218880b3bf3b47ab49022e"

  strings:
    $s1 = "GUGU?@" fullword ascii
    $s2 = "wOKe[2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}