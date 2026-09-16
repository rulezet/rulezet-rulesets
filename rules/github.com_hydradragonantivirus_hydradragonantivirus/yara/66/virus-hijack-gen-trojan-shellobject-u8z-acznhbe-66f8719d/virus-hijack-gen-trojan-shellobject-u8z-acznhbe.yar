rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aCZnhbe {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aCZnhbe.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d14071e2751008cdb3e8d97e9fd4ceaec134872ff86538fa05d807bf219bd7b7"

  strings:
    $s1 = "savailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}