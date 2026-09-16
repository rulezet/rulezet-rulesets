rule Virus_Hijack_Gen_Trojan_ShellObject_z8Z_aCZnhbe_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.z8Z@aCZnhbe_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "048606c37f5d231ab19ede9ffd7e9d4eee2b0e5ec876b8c1f70ab69cb26c96e3"

  strings:
    $s1 = "@+available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}