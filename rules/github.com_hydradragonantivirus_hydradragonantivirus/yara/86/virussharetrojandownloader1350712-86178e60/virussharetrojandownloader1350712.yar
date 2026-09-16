rule VirusShareTrojanDownLoader1350712 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader1350712.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea6ff8e30d198df70d81c3c7d1e94d38b3fbd0cfe8144ca85feae9af28848eb7"

  strings:
    $s1 = "a1D53RVXwXm81uTM9U.yjGhTavwGxhaP0cFia/uK83vURbPk0nGpMFiD/CAbPUapbqS0heH936s`1[[System.Object, mscorlib, Version=2.0.0.0, Culture" ascii
    $s2 = "<Module>{7E394785-9156-49A7-8ECE-B115ACFF894E}" fullword ascii
    $s3 = "3>SAId*6Ocr" fullword ascii
    $s4 = "{paTH@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}