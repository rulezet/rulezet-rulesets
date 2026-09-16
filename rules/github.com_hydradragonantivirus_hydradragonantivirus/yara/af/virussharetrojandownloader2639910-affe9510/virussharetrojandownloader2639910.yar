rule VirusShareTrojanDownLoader2639910 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader2639910.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1bfad96ffb4553eb1591050af4217f2664b599d2081bd6e8c1237c793fa3484"

  strings:
    $s1 = "c:\\users\\y\\documents\\visual studio 2010\\Projects\\WindowsApplication1\\WindowsApplication1\\obj\\x86\\Debug\\WindowsApplica" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}