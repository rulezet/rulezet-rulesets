rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e8c6cee20b840d1a987c30a1f8c747f1b555bd1b517ed3193c15e293cf94522"

  strings:
    $s1 = "lavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}