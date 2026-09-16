rule Virus_Hijack_Gen_Trojan_ShellObject_hHZ_ayM4QWg_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.hHZ@ayM4QWg_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbe7c87c03e8faefc0866fda7c72b17df06d457a23142da2baec605259ddad55"

  strings:
    $s1 = ".$YeEl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}