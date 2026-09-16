rule Virus_Hijack_Gen_Trojan_ShellObject_oSZ_aaT6Wyj_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oSZ@aaT6Wyj_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0259032c2385de41048e2d2506d26ef8a494c77365839b962e5fb284aed9fc80"

  strings:
    $s1 = "Mozilla/5.0 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)" fullword ascii
    $s2 = "Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)" fullword ascii
    $s3 = "My mommy is angry" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}