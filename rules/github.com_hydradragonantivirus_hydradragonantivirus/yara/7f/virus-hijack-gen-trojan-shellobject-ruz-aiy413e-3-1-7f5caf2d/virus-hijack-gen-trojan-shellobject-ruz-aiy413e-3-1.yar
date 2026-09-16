rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aiy413e_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aiy413e_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3022fb66d447ab9be852c2c8744ab6e3075ec1284ab75365632ddf05cd037bb"

  strings:
    $s1 = "VASE, " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}