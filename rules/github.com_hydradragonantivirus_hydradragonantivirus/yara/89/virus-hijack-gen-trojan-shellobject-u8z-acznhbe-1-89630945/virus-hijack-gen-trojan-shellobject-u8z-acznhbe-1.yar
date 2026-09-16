rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aCZnhbe_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aCZnhbe_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbb363b454b3a0ba3e83e10bef5cdc0402c26b320172d6a06bd4a9227d6ccf42"

  strings:
    $s1 = ":Zavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}