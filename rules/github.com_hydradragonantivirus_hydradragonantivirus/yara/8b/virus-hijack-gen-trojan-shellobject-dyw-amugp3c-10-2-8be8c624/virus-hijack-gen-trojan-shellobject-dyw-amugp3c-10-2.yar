rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_amUgp3c_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@amUgp3c_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df7a163658cfaa91983c6eb09e49b177b7b0bb419a30267b748d2359702b4531"

  strings:
    $s1 = "wiSt,r" fullword ascii
    $s2 = "HeNT$/" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}