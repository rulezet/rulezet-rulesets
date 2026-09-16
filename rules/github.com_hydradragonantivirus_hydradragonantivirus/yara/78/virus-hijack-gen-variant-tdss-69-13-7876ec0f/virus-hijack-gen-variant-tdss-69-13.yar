rule Virus_Hijack_Gen_Variant_TDss_69_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.TDss.69_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc449b41b3dbe4067b81f2b0e50a8da7c3143d942cfdd3bd4ddc3ba478a6c6aa"

  strings:
    $s1 = " 2000-2010 FRISK Software International" fullword wide
    $s2 = "F-PROT Antivirus for Windows" fullword wide
    $s3 = "Icon in the taskbar notification area (F-PROT Antivirus)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}