rule VirusShareTrojanDownLoader3352739 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader3352739.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58c6852bb4e71cea496457edf3ea321568c0ccafeb00d88fb0bc8cafee563852"

  strings:
    $s1 = "eZGOhwHsUbVjUNjdZQ.ebjl5iduDGjiB8jAyt/ebNkJCKLpIQ7WNEyry/eqCFI34cEJo0UnCQSg`1[[System.Object, mscorlib, Version=2.0.0.0, Culture" ascii
    $s2 = "<Module>{28C8E85B-C528-4B0C-AA42-BCDEF36D10A5}" fullword ascii
    $s3 = ";ANsA(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}