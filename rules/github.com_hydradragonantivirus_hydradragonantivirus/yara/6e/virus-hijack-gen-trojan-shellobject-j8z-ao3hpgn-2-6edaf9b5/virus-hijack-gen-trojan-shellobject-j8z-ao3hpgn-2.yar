rule Virus_Hijack_Gen_Trojan_ShellObject_J8Z_aO3hPGn_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.J8Z@aO3hPGn_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "616a7e16d764b65797c018bcd107984510a348a1eb662371705d4b7f9bfe4204"

  strings:
    $s1 = "hU;ShUT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}