rule Trojan_Danger_Generic_Dacic_1A7FA519_A_A7E5144F_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.A7E5144F_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da7938f690166eac3f0c6d90df26c82254378274933c4e33da72bf358361b61a"

  strings:
    $s1 = "qSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}