rule Virus_Hijack_Gen_Trojan_ShellObject_pyZ_aeWgNZc_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aeWgNZc_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f34f3e1d3d0fa5328a5524596305b034e7f13602f2966ca6b4b77035ddde53d"

  strings:
    $s1 = "Reminder dialog information http://www.rarlab.com/themes.htm" fullword wide
    $s2 = "Enable Itanium executable compression" fullword wide
    $s3 = "Wipe files if &password is set" fullword wide
    $s4 = "Show archive contents" fullword wide
    $s5 = "Band%d" fullword wide
    $s6 = "Open in associated application" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}