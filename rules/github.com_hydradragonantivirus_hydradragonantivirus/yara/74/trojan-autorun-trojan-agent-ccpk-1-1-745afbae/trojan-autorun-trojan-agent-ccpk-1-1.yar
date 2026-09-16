rule Trojan_Autorun_Trojan_Agent_CCPK_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Agent.CCPK_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "601f88154ff1b55e69262c3aa7f18c10726ab82480d43d5c6d87e1a32448dcda"

  strings:
    $s1 = "6User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}