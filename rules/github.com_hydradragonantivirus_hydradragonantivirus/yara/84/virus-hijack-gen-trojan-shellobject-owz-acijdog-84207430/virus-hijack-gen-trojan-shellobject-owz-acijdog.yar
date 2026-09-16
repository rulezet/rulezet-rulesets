rule Virus_Hijack_Gen_Trojan_ShellObject_OWZ_aCIJdog {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.OWZ@aCIJdog.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bf1826f046c21f5cf48201fdaf0a27c33c409e03ff038d3e560a469f1218a43"

  strings:
    $s1 = "q{functionality of the programs. You have 30 days from the delivery date to evaluate these programs. If you decide to use any" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}