rule Virus_Hijack_Gen_Trojan_ShellObject_wSZ_a8YIsUn_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wSZ@a8YIsUn_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7686fe6783f3953869650227af0386ba2aa20047f0c24e6bcfce47bfd3a6b7ec"

  strings:
    $s1 = "agreements or representations, written or oral, regarding such programs and/or service`" fullword ascii
    $s2 = "<remainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}