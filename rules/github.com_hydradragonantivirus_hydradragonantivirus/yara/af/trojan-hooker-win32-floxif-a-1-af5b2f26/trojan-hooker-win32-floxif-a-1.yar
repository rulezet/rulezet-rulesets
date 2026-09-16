rule Trojan_Hooker_Win32_Floxif_A_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b060bfc3736d0abb9a81e525f1264fdd33e8a3dcd8182ebac3ad16924961b7bf"

  strings:
    $s1 = "Profiler detected" fullword wide
    $s2 = "Loop broken" fullword wide
    $s3 = "   <description>Application description here</description>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}