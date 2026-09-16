rule Virus_Hijack_Gen_Trojan_ShellObject_iuZ_amBwvTb_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iuZ@amBwvTb_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92af4f866ca9cc649354ca6d381fb9ec3788769251ccdaf2a8bd12e74b36fbf5"

  strings:
    $s1 = "wORT;h" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}