rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0533846b242bb688e44afc1f953864dda67f94cdccac9b884495977b68b34a13"

  strings:
    $s1 = "Kavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}