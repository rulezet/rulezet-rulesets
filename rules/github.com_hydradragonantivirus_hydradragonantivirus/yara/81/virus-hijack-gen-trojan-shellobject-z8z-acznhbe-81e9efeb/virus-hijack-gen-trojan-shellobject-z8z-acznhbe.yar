rule Virus_Hijack_Gen_Trojan_ShellObject_z8Z_aCZnhbe {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.z8Z@aCZnhbe.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b7ab9fbc19843fc25f0f25e082c3c3b6d9ae86b75ae2b094b267beec168c386"

  strings:
    $s1 = "Y:available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}