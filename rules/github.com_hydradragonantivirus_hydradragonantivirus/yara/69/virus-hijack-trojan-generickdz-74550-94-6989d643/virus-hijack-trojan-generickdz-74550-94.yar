rule Virus_Hijack_Trojan_GenericKDZ_74550_94 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_94.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8f942d8958e607ca1b99db832536257ef3c4ada166c0d10645b696a033257fb"

  strings:
    $s1 = "Dir `/srv/git/wk_mkchild/var/url_processor` is empty. Sleep and goto new cycle" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}