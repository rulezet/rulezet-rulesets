rule Virus_Hijack_Gen_Trojan_ShellObject__JZ_ayM4QWg_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@JZ@ayM4QWg_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9dfbf90cd49ba9779c946f6acf1822b2de327251268b1302a5efb6fce650ebac"

  strings:
    $s1 = "BinO,V<i=o*" fullword ascii
    $s2 = "This pr9og" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}