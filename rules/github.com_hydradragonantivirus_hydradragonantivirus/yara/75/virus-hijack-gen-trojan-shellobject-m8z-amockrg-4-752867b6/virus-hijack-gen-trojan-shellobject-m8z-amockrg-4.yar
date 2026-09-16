rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76f867867fd18eaaa663cc4356d6059149f3431e9a427cd20ecf5f09623da86b"

  strings:
    $s1 = "gassets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}