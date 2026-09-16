rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_aKo42Jj_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83f871ffc39fceeb5427d27aa34bb8e121b97e00d082a943ce795cd9396d9606"

  strings:
    $s1 = "]\\0\"LORA&2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}