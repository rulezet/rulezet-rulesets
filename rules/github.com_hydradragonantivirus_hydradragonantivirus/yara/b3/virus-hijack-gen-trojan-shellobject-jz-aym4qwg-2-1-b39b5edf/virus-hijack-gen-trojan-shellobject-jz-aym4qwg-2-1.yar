rule Virus_Hijack_Gen_Trojan_ShellObject__JZ_ayM4QWg_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@JZ@ayM4QWg_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75157ae7772d2221448144147d521f147b7b475f8ebcd691bb363f8d90c5edda"

  strings:
    $s1 = "BinO,V<i=o*" fullword ascii
    $s2 = "This pr9og" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}