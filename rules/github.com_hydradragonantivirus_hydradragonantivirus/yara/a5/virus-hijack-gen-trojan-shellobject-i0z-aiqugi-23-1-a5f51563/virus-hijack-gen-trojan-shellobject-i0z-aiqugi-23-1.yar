rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_23_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cc06f2167da90d33e5461f91eac3bc08bf507de2fdb7f145728a320d409144c"

  strings:
    $s1 = "ooze:|D" fullword ascii
    $s2 = "qUAr#O" fullword ascii
    $s3 = "b;omeN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}