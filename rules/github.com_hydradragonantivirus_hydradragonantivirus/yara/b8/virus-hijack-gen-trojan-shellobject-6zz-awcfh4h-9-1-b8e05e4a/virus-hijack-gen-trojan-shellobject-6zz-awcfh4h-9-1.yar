rule Virus_Hijack_Gen_Trojan_ShellObject_6zZ_aWcfH4h_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.6zZ@aWcfH4h_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84ac255477920ed668e22f700aacd20b8c8b8067cc8a6d93be6efb8bd2270fb3"

  strings:
    $s1 = "nad964g>milA><oFuqtIFDwN}y|QNL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}