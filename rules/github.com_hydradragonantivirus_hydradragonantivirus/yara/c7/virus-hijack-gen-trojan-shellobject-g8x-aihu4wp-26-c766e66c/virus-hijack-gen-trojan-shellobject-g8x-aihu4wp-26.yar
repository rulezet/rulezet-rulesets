rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_26 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "021d543f7d9fc17b05d48bbf146cd7bf53cac9f5194197557febf5e110653343"

  strings:
    $s1 = "Blaeberry" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}