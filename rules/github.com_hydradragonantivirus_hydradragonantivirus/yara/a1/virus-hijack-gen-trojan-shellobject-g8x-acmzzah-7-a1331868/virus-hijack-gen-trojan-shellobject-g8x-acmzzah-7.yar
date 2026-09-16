rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCMzZah_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCMzZah_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13f1df570f511bba346e27a70a38120740623a4f6f78a344b95124c9fdc3615f"

  strings:
    $s1 = "Souter" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}