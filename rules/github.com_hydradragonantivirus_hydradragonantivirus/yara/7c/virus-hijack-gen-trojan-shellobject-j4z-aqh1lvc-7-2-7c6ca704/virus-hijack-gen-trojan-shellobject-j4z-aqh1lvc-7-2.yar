rule Virus_Hijack_Gen_Trojan_ShellObject_j4Z_aqH1LVc_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2f233ce8d18552b2b93525dc9cc0ed88be7b327716dbdc8eb85f1145a0424c3"

  strings:
    $s1 = "BALI:'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}