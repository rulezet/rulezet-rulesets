rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e77e37de83d3af91ba4fcfaf0db510defa494c830fd1aaa3988f8f9745566f90"

  strings:
    $s1  = "7z SFX Constructor v4.5.0.0 (http://usbtor.ru/viewtopic.php?t=798)" fullword wide
    $s2  = "A build of the Launcher for TeraCopy Portable, allowing it to be run from a removable drive." fullword wide
    $s3  = "PortableApp Launcher" fullword wide
    $s4  = "TeraCopy Portable Launcher" fullword wide
    $s5  = ";Project created in program 7z SFX Constructor" fullword ascii
    $s6  = "Copyright (C) 2007-2021 Code Sector Inc." fullword wide
    $s7  = "direction;" fullword ascii
    $s8  = "AshY(\"" fullword ascii
    $s9  = "!sNed*/&" fullword ascii
    $s10 = "Disable r" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}