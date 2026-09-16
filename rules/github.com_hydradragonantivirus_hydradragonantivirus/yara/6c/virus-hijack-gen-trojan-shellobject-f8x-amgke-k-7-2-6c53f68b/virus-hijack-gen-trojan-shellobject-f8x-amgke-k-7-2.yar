rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_amgke_k_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@amgke!k_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb71576657f290b1a7144ecac96ac94541b4aefc20f43db270511d9ce6580db6"

  strings:
    $s1 = "<description>Windows Error Reporting</description>" fullword ascii
    $s2 = "AEvent is set to bypass quarantine" fullword wide
    $s3 = "CFeedback pipe (SQM/CEIP) enabled?" fullword wide
    $s4 = "@!error: wrong format for ansi string!" fullword wide
    $s5 = "AHKCU\\Software\\Microsoft\\Internet Explorer\\Settings\\Anchor Color" fullword ascii
    $s6 = "$@Unknown exception" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}