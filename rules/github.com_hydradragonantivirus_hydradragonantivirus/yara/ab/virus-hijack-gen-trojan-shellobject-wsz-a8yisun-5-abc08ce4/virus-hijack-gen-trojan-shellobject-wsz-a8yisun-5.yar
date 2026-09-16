rule Virus_Hijack_Gen_Trojan_ShellObject_wSZ_a8YIsUn_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wSZ@a8YIsUn_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11685705bb3bd76238f53acad91c2cbc40666d46b54d5fc0c0f6eedd0656e244"

  strings:
    $s1 = "$remainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}