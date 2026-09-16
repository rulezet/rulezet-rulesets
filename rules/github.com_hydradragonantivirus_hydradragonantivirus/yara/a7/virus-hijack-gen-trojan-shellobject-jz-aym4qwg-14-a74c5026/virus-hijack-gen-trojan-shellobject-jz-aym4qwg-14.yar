rule Virus_Hijack_Gen_Trojan_ShellObject__JZ_ayM4QWg_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@JZ@ayM4QWg_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e1908c5818fc33b673232d3f275aab2f3a6e887993adf8f914624620aa84d41"

  strings:
    $s1 = "QERe%E1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}