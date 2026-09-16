rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aKiV4Tf {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aKiV4Tf.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1eb0f1fbe183d8fae8ca3e684cc7ae8359273eaefee10b2b6770ded8d8a046d8"

  strings:
    $s1 = "RUvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}