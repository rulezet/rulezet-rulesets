rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc8c0189c876a37b953d53329705ef7d3d7e809476ea84ddd0f0edf527ed2990"

  strings:
    $s1 = "&posted a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}