import "pe"
rule _Virus_Autorun_Trojan_GenericKDZ_94539_Virus_Autorun_Trojan_Gene_144 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Trojan.GenericKDZ.94539.vir, Virus.Autorun_Trojan.GenericKDZ.94539_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_744_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac8ba066da22f190269552d5ddcb76a46a2489cf07b9a2aacab81783969824a6"
    hash2       = "f22b4fc7464b6b4f3898dd794b3e0d9563acf20da2d621df0958df2d827cdeee"
    hash3       = "fb6cd31a4300024677fabb36cabbbc528626aa74ae7e726361e312406ae58845"

  strings:
    $x1  = "\\drivers32\\World War II - Frontline Command Serial Generator.exe" fullword ascii
    $x2  = "\\drivers32\\World War II - Frontline Command No-Cd Crack.exe" fullword ascii
    $x3  = "\\drivers32\\Tomb Raider - The Angel of Darkness No-Cd Crack.exe" fullword ascii
    $x4  = "\\drivers32\\Tomb Raider - The Angel of Darkness Serial Generator.exe" fullword ascii
    $x5  = "\\drivers32\\Commandos 3 - Destination Berlin No-Cd Crack.exe" fullword ascii
    $x6  = "\\drivers32\\Age of Mythology - The Titans Serial Generator.exe" fullword ascii
    $x7  = "\\drivers32\\Age of Mythology - The Titans No-Cd Crack.exe" fullword ascii
    $x8  = "\\drivers32\\Commandos 3 - Destination Berlin Serial Generator.exe" fullword ascii
    $s9  = "\\drivers32\\Star Wars - Knights of the Old Republic Serial Generator.exe" fullword ascii
    $s10 = "\\drivers32\\Star Wars - Knights of the Old Republic No-Cd Crack.exe" fullword ascii
    $s11 = "\\drivers32\\Counter-Strike - Condition Zero No-Cd Crack.exe" fullword ascii
    $s12 = "\\drivers32\\Civilization III - Conquest Serial Generator.exe" fullword ascii
    $s13 = "\\drivers32\\Counter-Strike - Condition Zero Serial Generator.exe" fullword ascii
    $s14 = "\\drivers32\\Civilization III - Conquest No-Cd Crack.exe" fullword ascii
    $s15 = "\\drivers32\\Dark Age of Camelot - Trials of Atlantis Serial Generator.exe" fullword ascii
    $s16 = "\\drivers32\\Flight Simulator - Century of Flight No-Cd Crack.exe" fullword ascii
    $s17 = "\\drivers32\\Warlords IV - Heroes of Etheria Serial Generator.exe" fullword ascii
    $s18 = "\\drivers32\\Sniper Elite - Berlin 1943 No-Cd Crack.exe" fullword ascii
    $s19 = "\\drivers32\\Elder Scrolls III - Tribunal No-Cd Crack.exe" fullword ascii
    $s20 = "\\drivers32\\Freedom - Soldiers of Liberty Serial Generator.exe" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d91adc8b0bbe064a5d31cc207c0180f7" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}