rule VirusShareTrojanSiggen1527233 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1527233.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b514ceb4004e2f94a4770d77b2476ab356c7de0a86a465a26953757896dffad"

  strings:
    $s1 = "erein and in the repository at https://www.certum.pl/repository.0" fullword ascii
    $s2 = "Usage of this certificate is strictly subjected to the CERTUM Certification Practice Statement (CPS) incorporated by reference h" ascii
    $s3 = "&Open Source Developer, Oliver Valencia100." fullword ascii
    $s4 = "TAro*!\\j" fullword ascii
    $s5 = "Open Source Developer1/0-" fullword ascii
    $s6 = " 2021 Animetrick. All Rights Reserved" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}