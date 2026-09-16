rule Virus_Hijack_Gen_Variant_TDss_69_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.TDss.69_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8efcdc6fb1390955311cf45aca6ac6e9d883969b1619dca9d7b08872d746d5f5"

  strings:
    $s1 = " 2000-2010 FRISK Software International" fullword wide
    $s2 = "F-PROT Antivirus for Windows" fullword wide
    $s3 = "Icon in the taskbar notification area (F-PROT Antivirus)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}