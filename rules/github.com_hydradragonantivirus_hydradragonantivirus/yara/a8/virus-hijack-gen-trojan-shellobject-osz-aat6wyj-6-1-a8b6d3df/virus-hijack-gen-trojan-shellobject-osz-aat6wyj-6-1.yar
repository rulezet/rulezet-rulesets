rule Virus_Hijack_Gen_Trojan_ShellObject_oSZ_aaT6Wyj_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oSZ@aaT6Wyj_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac18c925fff64bf07be963b2b94fef73ac64f721e29f64a5b5e715df610ecffa"

  strings:
    $s1 = "Select CommandLine from Win32_Process where Name='{0}'" fullword wide
    $s2 = "SELECT Name, VideoProcessor FROM Win32_VideoController" fullword wide
    $s3 = "Shell Infrastructure Host" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}