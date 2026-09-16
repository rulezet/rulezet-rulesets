rule Virus_Autorun_Dump_Win32_Mydoom_M_mm_198_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Win32.Mydoom.M@mm_198_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "598bba986e072ada37a571b9c2af4c5a95e2903b4a57a673fd3980e039d55d23"

  strings:
    $s1 = "`KaPa`a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}