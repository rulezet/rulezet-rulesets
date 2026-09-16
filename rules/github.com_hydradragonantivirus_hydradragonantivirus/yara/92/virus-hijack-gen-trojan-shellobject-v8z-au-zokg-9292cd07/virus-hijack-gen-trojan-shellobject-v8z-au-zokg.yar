rule Virus_Hijack_Gen_Trojan_ShellObject_v8Z_au_Zokg {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v8Z@au@Zokg.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a985d55b5cf68c5fa33bff58de1a77c263d158779b6f48185d99d9f369249835"

  strings:
    $s1 = "2University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}