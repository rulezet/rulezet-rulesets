rule Virus_Hijack_Gen_Trojan_ShellObject__JZ_ayM4QWg_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@JZ@ayM4QWg_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d102e32aacb7e4c45d72266db1c567d50d39bb60ca84d630c5728719bcb456e8"

  strings:
    $s1 = "BinO,V<i=o*" fullword ascii
    $s2 = "This pr9og" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}