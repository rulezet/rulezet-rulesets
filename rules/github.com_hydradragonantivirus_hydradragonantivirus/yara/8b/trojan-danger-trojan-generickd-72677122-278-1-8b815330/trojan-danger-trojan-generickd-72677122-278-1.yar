rule Trojan_Danger_Trojan_GenericKD_72677122_278_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_278_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "206c552633ae6f985faa75adc9b79981666897042fdaac5771f5fcc5b4e7b111"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "nstall System v3.06.1</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><request" ascii
    $s3 = "CreateShortcut: out: \"%s\", in: \"%s %s\", icon: %s,%d, sw=%d, hk=%d" fullword ascii
    $s4 = "0Razer Driver Uninstalle" fullword wide
    $s5 = "Razer PID0257 Driver Uninstaller" fullword wide
    $s6 = "\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><support" ascii
    $s7 = " 2022 Razer Inc. All rights reserved" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}