rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d1ca60a777f611d7a11359bd0efcb1cb5eed1cba2d06d4de41d1cf811149a0f"

  strings:
    $s1 = "BOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}