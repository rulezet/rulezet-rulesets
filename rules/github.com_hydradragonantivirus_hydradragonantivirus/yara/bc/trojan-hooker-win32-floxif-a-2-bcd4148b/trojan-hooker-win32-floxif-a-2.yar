rule Trojan_Hooker_Win32_Floxif_A_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27b5a6b9a963f178a0130b9dbdf73dcd1dd9dc19e027994a29433690dae0f397"

  strings:
    $s1 = "c:\\Documents and Settings\\Administrator\\My Documents\\Visual Studio 2008\\Projects\\SmadavUpdater1472\\Release\\SmadavSeconda" ascii
    $s2 = "c:\\Documents and Settings\\Administrator\\My Documents\\Visual Studio 2008\\Projects\\SmadavUpdater1472\\Release\\SmadavSeconda" ascii
    $s3 = "SmadavSecondaryUpdater, Version 1.2" fullword wide
    $s4 = "Update Starting" fullword wide
    $s5 = "Update Smadav [Click Here]" fullword wide
    $s6 = "Update Now [Click Here]" fullword wide
    $s7 = "About SmadavSecondaryUpdater" fullword wide
    $s8 = "build 2023.1.2" fullword wide
    $s9 = "Smadav Updater Assistance" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}