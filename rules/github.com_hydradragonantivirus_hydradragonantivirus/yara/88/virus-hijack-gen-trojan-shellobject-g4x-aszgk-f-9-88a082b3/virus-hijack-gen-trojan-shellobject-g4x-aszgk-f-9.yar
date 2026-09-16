rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e281018e5541eff20b6b062e8d6bbd557450fd4cfe942c85a6271a09ff719b8"

  strings:
    $s1 = "vOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}