rule VirusShareTrojanLoaderNET6 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanLoaderNET6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa558ca6d275da03c25907670fd9717e5979715d376b46051882fd27c153cefa"

  strings:
    $s1 = "Password Protection Service.exe" fullword wide
    $s2 = "Password Protection Service" fullword wide
    $s3 = "Password Protection Service " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}