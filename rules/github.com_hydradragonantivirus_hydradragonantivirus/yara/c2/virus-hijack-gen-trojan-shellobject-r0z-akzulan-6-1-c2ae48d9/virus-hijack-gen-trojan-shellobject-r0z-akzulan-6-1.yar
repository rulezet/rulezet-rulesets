rule Virus_Hijack_Gen_Trojan_ShellObject_r0Z_aKzulAn_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r0Z@aKzulAn_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7478f7dd1138fa378134f046e0a831ffddb94cdcb9d3e956ff81d6656f12213"

  strings:
    $s1 = "c?TUnNY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}