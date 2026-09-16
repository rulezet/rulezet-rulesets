rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_aiy413e_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@aiy413e_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b82aaa2f7f2853f7eccdae9d71b2d2388ac5c643c7d942efd4cbf8becd450438"

  strings:
    $s1 = ".*mEwl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}