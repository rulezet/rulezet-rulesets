rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb6d5165eade8df8c8a698723a8ea33ee4f4945a158d88b3dd5a93a7b8164e64"

  strings:
    $s1 = "VpOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}