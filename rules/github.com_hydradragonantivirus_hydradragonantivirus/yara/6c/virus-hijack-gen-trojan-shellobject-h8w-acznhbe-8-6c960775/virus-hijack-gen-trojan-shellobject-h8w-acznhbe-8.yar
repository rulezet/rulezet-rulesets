rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3904290eb85b1cfcda7de73be6d58145522ee2e4225bce2b6156964ae90a836c"

  strings:
    $s1 = "Xavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}