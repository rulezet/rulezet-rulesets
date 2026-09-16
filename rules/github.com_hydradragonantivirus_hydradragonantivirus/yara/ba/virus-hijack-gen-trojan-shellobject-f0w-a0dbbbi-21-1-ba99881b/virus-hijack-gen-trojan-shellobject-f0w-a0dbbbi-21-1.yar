rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_21_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37ef175dffe0763ffdf71f099d4f3ac03708f37ad29ebd42ffd137da727ea1a5"

  strings:
    $s1 = "Mozilla/5.0 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)" fullword ascii
    $s2 = "Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)" fullword ascii
    $s3 = "Don't beat me, I am a child ;(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}