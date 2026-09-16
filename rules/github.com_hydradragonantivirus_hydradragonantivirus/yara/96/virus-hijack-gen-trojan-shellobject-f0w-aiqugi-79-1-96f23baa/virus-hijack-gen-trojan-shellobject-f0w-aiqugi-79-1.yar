rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_79_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_79_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a47f3a520b627eb14866eb416e2d0a7b9dcbca7276b69705ce332aac9927988d"

  strings:
    $s1 = "Can not run Unicode version of ATL70.DLL on Windows 95, Windows98 or Windows Me." fullword ascii
    $s2 = "|Microsoft Visual C++ Runtime Library" fullword ascii
    $s3 = "Created by MIDL version 6.00.0347 at Fri Aug 25 22:17:47 2006" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}