rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amIMPvn_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amIMPvn_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b85a2cad9763b0405be7d1ad3cd5ffe67b2025098960458f29b83e1fc36c217b"

  strings:
    $s1 = "CNLBaseException::TraceException - Exception Thrown(searchindexer) - %08X, Line:%d, File:%S" fullword wide
    $s2 = "<description>Microsoft Search</description>" fullword ascii
    $s3 = "?Cleanup@CSearchServiceObj@@SAHXZ" fullword ascii
    $s4 = "Software\\Microsoft\\Windows Search\\Gathering Manager" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}