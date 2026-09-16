rule Virus_Hijack_Gen_Trojan_ShellObject_UzZ_aCEmdoo_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.UzZ@aCEmdoo_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87d02ae8376d630f4e9cac49e24808b16b8ae78f2ee67a944be97b0425b685e7"

  strings:
    $s1 = "La*@HOgGy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}