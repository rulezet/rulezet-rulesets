rule Virus_Hijack_Gen_Trojan_ShellObject_dyX_amUgp3c_11_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyX@amUgp3c_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0700a8cde0d9ddd40d3893ed54b9daadf30716ef00da2d632a506709336624c6"

  strings:
    $s1 = ">?NiDe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}