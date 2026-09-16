rule Virus_Hijack_Gen_Trojan_ShellObject_DyZ_aSgChKg_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DyZ@aSgChKg_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49b178de470facec7306d844d9d6525e513d19ee30d99c065d831e744b7b2c75"

  strings:
    $s1 = ",@SPeal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}