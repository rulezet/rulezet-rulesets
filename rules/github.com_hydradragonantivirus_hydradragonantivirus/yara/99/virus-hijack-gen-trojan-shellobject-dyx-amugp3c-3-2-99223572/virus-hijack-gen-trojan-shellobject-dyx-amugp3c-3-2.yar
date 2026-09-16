rule Virus_Hijack_Gen_Trojan_ShellObject_dyX_amUgp3c_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyX@amUgp3c_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4547b5929d307655b670cedd6a14e8d7cd74912d411bc6f242f677cd8f6ac22"

  strings:
    $s1 = "(zScA~,nIzY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}