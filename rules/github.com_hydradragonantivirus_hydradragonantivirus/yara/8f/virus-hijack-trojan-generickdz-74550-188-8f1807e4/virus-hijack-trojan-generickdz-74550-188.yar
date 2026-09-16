rule Virus_Hijack_Trojan_GenericKDZ_74550_188 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_188.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c022e9480340cadaface7975acda8755999b898a1fdc7160dcb7386be7dc9d4f"

  strings:
    $s1 = "Dir `/srv/git/wk_mkchild/var/url_processor` is empty. Sleep and goto new cycle" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}