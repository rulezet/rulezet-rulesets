rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_65_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_65_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87d44ff5c5288094440d7fcc2c365c03a744cc0905fc7827212ecd3e9ff16410"

  strings:
    $s1 = "CNLBaseException::TraceException - Exception Thrown(searchindexer) - %08X, Line:%d, File:%S" fullword wide
    $s2 = "<description>Microsoft Search</description>" fullword ascii
    $s3 = "Main Service Thread" fullword ascii
    $s4 = "?Cleanup@CSearchServiceObj@@SGHXZ" fullword ascii
    $s5 = "Catalog move: file copy" fullword ascii
    $s6 = "Software\\Microsoft\\Windows Search\\Gathering Manager" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}