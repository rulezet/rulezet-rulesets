rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4917874662402a8e7aaccb65cd2430f69de825f0e71b8af21ec2d0af44084d1"

  strings:
    $s1 = "EboE Xk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}