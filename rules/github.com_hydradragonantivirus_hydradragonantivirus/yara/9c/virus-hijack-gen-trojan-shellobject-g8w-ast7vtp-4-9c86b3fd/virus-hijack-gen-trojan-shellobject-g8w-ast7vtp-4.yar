rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aSt7VTp_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aSt7VTp_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f301639639a94ed4c6409b14c18a8d181a315c85a233cef967cfa3f0d0baf0c"

  strings:
    $s1 = "jpurchase orders transmitted from Oracle Purchasing, during a 12 month period. You may not exceed the licensed number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}