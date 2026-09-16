rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_a8oG5if {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@a8oG5if.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b301bf5c0c868455973df72e357c7466df638dda676c6b8d64d1fee0866610e2"

  strings:
    $s1 = "u%by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}