rule Virus_Hijack_Gen_Trojan_ShellObject_e4Y_a05ilOd_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4Y@a05ilOd_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c68a1f62c081cf4074063ff8f095898379882b2e561779bd21291ef929fd8bdb"

  strings:
    $s1 = "6c76=;j>>k?>ECrFFsGFMKzNN{ONUS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}