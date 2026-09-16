rule Virus_Hijack_Gen_Trojan_ShellObject_e4X_a8K8N6h_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4X@a8K8N6h_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9845f7ccd500feffb8009add5bc7a8e8b8fea322d2ea1f9ecf069f089d0dec26"

  strings:
    $s1 = "xmt!MADaM)_%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}