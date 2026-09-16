rule Virus_Danger_Gen_Trojan_ShellObject_t8Z_aKiV4Tf {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.t8Z@aKiV4Tf.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5744ffd41bacb25673934d614c87fd1630df0b6e9364bb130d542d75afec3bbd"

  strings:
    $s1 = "Vvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}