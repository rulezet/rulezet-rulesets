rule Virus_Hijack_Gen_Trojan_ShellObject_wSZ_a8YIsUn_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wSZ@a8YIsUn_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d1f21524207f82a7c79d977b1f5e2f7837ba54dc07b9dc57f96e480d533a710"

  strings:
    $s1 = "r[remainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}