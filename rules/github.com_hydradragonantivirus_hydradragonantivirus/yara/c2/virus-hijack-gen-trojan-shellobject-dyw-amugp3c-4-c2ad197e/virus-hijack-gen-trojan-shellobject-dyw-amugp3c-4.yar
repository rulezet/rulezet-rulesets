rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_amUgp3c_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@amUgp3c_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04e50012bbb06d00bb7c9793aa07839075cfca5ec4502feaa6337a341c5c5d80"

  strings:
    $s1 = "pLOW`N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}