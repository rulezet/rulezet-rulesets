rule Virus_Hijack_Gen_Trojan_ShellObject_wyZ_ai_DfO_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wyZ@ai@DfO_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6f49d464ef60fdcdd10f1b0475bd9360dc10a644b3a5c67d703d390582f1885"

  strings:
    $s1 = "tERP'I|g#\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}