rule Virus_Hijack_Gen_Trojan_ShellObject_CyZ_ayMBdto_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.CyZ@ayMBdto_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "265cc13ba64beb9a45ab32f4f79e23b29331fac9b6230a1096f7580d60a96836"

  strings:
    $s1 = "(LuNg)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}