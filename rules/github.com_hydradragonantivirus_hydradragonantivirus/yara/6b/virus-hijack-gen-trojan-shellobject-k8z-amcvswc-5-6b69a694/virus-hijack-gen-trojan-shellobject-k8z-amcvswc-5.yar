rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_amCvSwc_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@amCvSwc_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12c2d744352d3e6acef2736b332893e56d42dc8ee084fe7fa3bd242f75a4ba62"

  strings:
    $s1 = "?University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}