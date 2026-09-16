rule Virus_Hijack_Trojan_GenericKDZ_105924_145_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_145_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82606950058fcb5e5b57dc922169b7c7542dc404d1c9ed3531c8763769fff663"

  strings:
    $s1 = "/c ping 127.0.0.1 -n 1 && del /f/q \"%s\"" fullword ascii
    $s2 = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii
    $s3 = "Microsoft Windows Server 2016 Technical Preview" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}