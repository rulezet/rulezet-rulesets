rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_amUgp3c_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@amUgp3c_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e14a5961b862b7895012e88d13540ec39877a0f394f1d8e3ac6cb624beb1fc42"

  strings:
    $s1 = "%MANd]K" fullword ascii
    $s2 = "%MANd[J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}