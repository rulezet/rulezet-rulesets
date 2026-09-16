rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6103ea8ad656330d1c9a01eac0c131acbb9beb2e174a877bd28289d389307eef"

  strings:
    $s1 = "Bjby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}