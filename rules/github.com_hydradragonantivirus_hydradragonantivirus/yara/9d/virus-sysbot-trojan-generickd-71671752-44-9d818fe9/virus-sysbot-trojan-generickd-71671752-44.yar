rule Virus_Sysbot_Trojan_GenericKD_71671752_44 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_44.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80df419e2c11b9753c8d3a72445c3d22351acc7150c042a182cc8779ef78539c"

  strings:
    $s1 = "save recsound aaa" fullword ascii
    $s2 = "MSFT Corp" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}