rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aCZnhbe_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aCZnhbe_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3abca1ce39bc8b1db7a39697a209df117561131a62872292419e4bdc34cf3bf8"

  strings:
    $s1 = "yavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii
    $s2 = "CQ&cv]=hpt;brUTE[j" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}