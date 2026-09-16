rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154a245a98ba9ebe9fd262b435d3b713774f80244ad4ae8aed41eced009273e3"

  strings:
    $s1 = "*automatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}