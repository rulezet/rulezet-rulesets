rule Virus_Hijack_Gen_Trojan_ShellObject_EuZ_aiy413e_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbe838cdda71aee5680d73bdff2e5c62670f015ae8d084c0aebb765d54d39d7e"

  strings:
    $s1 = "NEon{Ds>,yeuj7P" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}