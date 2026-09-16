rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4b7c988c68ee144c9a3b98565be89b11701d46dc8fa67bee1d50b489d36ac2c"

  strings:
    $s1 = "\\My Shared Folder" fullword ascii
    $s2 = "ActiveMovie Control" fullword ascii
    $s3 = "AM1.0 QT PlugIn patch" fullword ascii
    $s4 = "ActiveMovie File Types" fullword ascii
    $s5 = "ZAM1.0 QT PlugIn patch" fullword ascii
    $s6 = "ui?nAIN" fullword ascii
    $s7 = "Microsoft PSS Notification Flag" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}