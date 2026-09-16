rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_aSgQ9ei_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@aSgQ9ei_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c6caa91bb0c492dc919fda935abf0c905c03abf2306b31b73a59ae758eddc6a"

  strings:
    $s1 = "7?ROBe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}