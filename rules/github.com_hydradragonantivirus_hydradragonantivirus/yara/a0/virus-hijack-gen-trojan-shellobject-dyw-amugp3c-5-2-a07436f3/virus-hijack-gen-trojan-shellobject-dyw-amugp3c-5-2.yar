rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_amUgp3c_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@amUgp3c_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d773ba69afda1b743964065d3977b54e134ea0ab33d1356438e712ccf6ad418a"

  strings:
    $s1 = ">?NiDe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}