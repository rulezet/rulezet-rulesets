rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34ee633410d764e30c3d80b414e1fa3ec96bea5abfe499fc66a59639a5aa05fe"

  strings:
    $s1 = "<Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}