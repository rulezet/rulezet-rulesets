rule Virus_Hijack_Gen_Trojan_ShellObject_dGX_aulKiep_14_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dGX@aulKiep_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fced43cb8b60465b877634cd0bb4e3b3cfa56846e663d3eba682e50c555158f4"

  strings:
    $s1 = "d!hooN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}