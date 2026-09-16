rule Virus_Hijack_Gen_Trojan_ShellObject_j4Z_aqH1LVc_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "667cc117b1e7ba7a1af02bece15cce1fa3cefb04febb99027dea9b28b5c57674"

  strings:
    $s1 = "\"jmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}