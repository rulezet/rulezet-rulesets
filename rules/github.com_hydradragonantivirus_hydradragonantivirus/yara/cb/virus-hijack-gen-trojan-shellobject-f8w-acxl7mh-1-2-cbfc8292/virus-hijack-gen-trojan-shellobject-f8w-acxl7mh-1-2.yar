rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCXl7mh_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCXl7mh_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502be20e0c18dd9fb2b017b45097a6704efcdb6346dd6bbda84c9c1e5f073773"

  strings:
    $s1 = "@?GeUM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}