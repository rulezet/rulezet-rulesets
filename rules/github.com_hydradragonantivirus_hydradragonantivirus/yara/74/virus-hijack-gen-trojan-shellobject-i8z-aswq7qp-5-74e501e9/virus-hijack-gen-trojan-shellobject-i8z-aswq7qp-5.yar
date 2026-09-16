rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aSWq7Qp_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aSWq7Qp_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a17311afdf889417e936439345f71f138a5cec5010d3a751125dfa12c8e09c1"

  strings:
    $s1 = "CNLBaseException::TraceException - Exception Thrown(searchindexer) - %08X, Line:%d, File:%S" fullword wide
    $s2 = "<description>Microsoft Search</description>" fullword ascii
    $s3 = "?Cleanup@CSearchServiceObj@@SAHXZ" fullword ascii
    $s4 = "Software\\Microsoft\\Windows Search\\Gathering Manager" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}