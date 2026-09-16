rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_aqza5Lj_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@aqza5Lj_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc390fe826f79b022edafa4e7c942308522f8879511a5f8951cc82aba8ed3af9"

  strings:
    $s1 = "WAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}