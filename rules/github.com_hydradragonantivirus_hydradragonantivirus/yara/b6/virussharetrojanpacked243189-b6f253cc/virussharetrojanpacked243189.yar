rule VirusShareTrojanPacked243189 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPacked243189.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16b0c001cc1b097e42f747df5bdcfa7d87312e17c5ad8adb0afc2928192a7de3"

  strings:
    $s1 = "Compiled AutoIT Script by CWAutComp v2.16" fullword ascii
    $s2 = "Adobe Acrobat Microsoft" fullword wide
    $s3 = "f}}yIRr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}