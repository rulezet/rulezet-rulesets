rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_56_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_56_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d7a24a7458dcd7b5e756a09d34fb4b3a0ccf8ba8c201400d5442777be5e9437"

  strings:
    $s1 = "DataGrid ActiveX Control - Version 6.0 (SP6)" fullword wide
    $s2 = "Microsoft DataGrid Control 6.0 (SP6) (OLEDB)WW" fullword ascii
    $s3 = "Microsoft DataGrid Control 6.0 (SP6) (OLEDB)" fullword ascii
    $s4 = ",Microsoft DataGrid Control 6.0 (SP6) (OLEDB)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}