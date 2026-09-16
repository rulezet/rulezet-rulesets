rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aOWVavp_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aOWVavp_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9284e30dd4875f66359735e20e073efd1108c81497ef9230c486bf747e013ec4"

  strings:
    $s1 = "Fneed dictionary" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}