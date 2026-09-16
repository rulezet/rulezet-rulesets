rule Virus_Hijack_Trojan_GenericKDZ_98388_243_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_243_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c4a377858348c4dd054d2c558de3536dfce94e5e1df4b76d1db82e41ae5210c"

  strings:
    $s1 = ">&PLex" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}