rule Trojan_Autorun_Gen_Trojan_Heur_D_cmIfbi3RsP_9_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2111c3418dcf68145dbb403f85cf1dec386c314dd3ccfd1d122580e39f1f7f79"

  strings:
    $s1 = "fyour order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}