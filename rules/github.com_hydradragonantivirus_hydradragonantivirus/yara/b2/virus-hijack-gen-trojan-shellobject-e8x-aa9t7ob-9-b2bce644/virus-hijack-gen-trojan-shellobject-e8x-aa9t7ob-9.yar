rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c6b31357d40fa33819e39728dd9e093086c36be7d111828f2eeaa35c0fa2d2f"

  strings:
    $s1 = "&(hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}