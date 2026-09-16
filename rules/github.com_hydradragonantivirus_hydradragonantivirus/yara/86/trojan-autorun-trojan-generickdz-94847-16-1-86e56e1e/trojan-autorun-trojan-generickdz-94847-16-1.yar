rule Trojan_Autorun_Trojan_GenericKDZ_94847_16_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d005d2a38ff20e806f098ef854e2f6571cf3aad62468130a21e360275963027a"

  strings:
    $s1 = "LTauthorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}