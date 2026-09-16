rule Virus_Hijack_Gen_Trojan_ShellObject_v8Z_aqDKVYh_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v8Z@aqDKVYh_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbf47c646ffdcd248b439d12410ea6abc0ef4838323b7442697d2cd06804207b"

  strings:
    $s1 = "Aorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}