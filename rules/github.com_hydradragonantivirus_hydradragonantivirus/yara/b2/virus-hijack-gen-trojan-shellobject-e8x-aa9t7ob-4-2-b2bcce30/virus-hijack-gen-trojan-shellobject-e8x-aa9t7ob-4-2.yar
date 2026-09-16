rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6143e80d28f382ac57c41eeab350f8be0e88f642211ae1726538685eb0686aa9"

  strings:
    $s1 = "Copyright (C) 2021 Microsoft. All rights reserved" fullword wide
    $s2 = "#D:YALI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}