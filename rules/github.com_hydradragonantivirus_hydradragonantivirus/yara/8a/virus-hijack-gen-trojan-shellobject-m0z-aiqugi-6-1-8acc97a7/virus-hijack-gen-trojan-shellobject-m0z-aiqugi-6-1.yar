rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "064f52340d4321f4185d176f48a821c4dc80592d7465e1af4b758754a113fd0a"

  strings:
    $s1 = "Lean Swapper v2" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}