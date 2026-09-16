rule Trojan_Hooker_Win32_Floxif_A_47 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_47.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45b11db319d25dd63e5501075e46fb138adf39d3f09b913f2af364b45f9ef5c6"

  strings:
    $s1 = "   <description>Application description here</description>" fullword ascii
    $s2 = "_f%boaR" fullword ascii
    $s3 = "Q@stum" fullword ascii
    $s4 = "E Rump" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}