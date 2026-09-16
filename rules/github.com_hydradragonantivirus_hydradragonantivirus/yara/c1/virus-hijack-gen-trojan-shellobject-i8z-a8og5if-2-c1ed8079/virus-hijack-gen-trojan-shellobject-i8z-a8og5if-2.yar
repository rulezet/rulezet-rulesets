rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_a8oG5if_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@a8oG5if_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d5b32d2acee313827e906bb4cc39c69d3a2f60f467b470e48ca19c3cb885ea8"

  strings:
    $s1 = "Wby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}