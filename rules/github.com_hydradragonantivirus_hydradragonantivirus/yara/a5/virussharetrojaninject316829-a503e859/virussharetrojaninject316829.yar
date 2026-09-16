rule VirusShareTrojanInject316829 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject316829.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d47f09cafc5757499fd7af9a61c0aec6bb95276ae85cf4e07ca931d0540c02c2"

  strings:
    $s1 = "Unable to create process}Quick Batch File Compiler Runtime Module Version 4.x" fullword wide
    $s2 = "Copyright (C) 2004-2019 Abyss Media Company, https://www.abyssmedia.com" fullword wide
    $s3 = "Unable to load script" fullword wide
    $s4 = "name=\"[APP TO TEST WITH]\"" fullword ascii
    $s5 = "Message`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}