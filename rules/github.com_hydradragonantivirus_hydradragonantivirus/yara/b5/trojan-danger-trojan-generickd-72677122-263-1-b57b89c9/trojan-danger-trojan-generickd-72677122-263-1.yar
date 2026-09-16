rule Trojan_Danger_Trojan_GenericKD_72677122_263_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_263_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7347abc0cfeaa1a0343174a0b3725e750a2edf5e47a76a3ac42e1736655ecc47"

  strings:
    $s1 = "Run it with /install on command line after an installation." fullword wide
    $s2 = "Run it with /uninstall on command line after an uninstallation." fullword wide
    $s3 = "Run it with /unregister on command line to clear its registration." fullword wide
    $s4 = "Run it with no command line to re-register only if re-registration is needed." fullword wide
    $s5 = "?Complete@UTxRegister@@YAXXZ" fullword ascii
    $s6 = "This program is used to register the version of apprentice in the current directory." fullword wide
    $s7 = "Apprentice Registration Server" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}