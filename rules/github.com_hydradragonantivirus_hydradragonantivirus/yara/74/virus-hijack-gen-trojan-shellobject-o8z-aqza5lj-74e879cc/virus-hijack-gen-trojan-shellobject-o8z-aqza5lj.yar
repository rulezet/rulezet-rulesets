rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_aqza5Lj {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@aqza5Lj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3448998e017bb6c913f3b4da354e2f8e687fa8ea1efa9fb955df156f9f9633cc"

  strings:
    $s1 = "j America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}