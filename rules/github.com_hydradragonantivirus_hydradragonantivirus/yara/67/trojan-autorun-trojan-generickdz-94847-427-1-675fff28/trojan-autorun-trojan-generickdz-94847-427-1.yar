rule Trojan_Autorun_Trojan_GenericKDZ_94847_427_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_427_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3a9b7b733a7ebe426b4302f7ad38eca58da003277f433edf2ae303cb9e3cc59"

  strings:
    $s1 = ")aAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}