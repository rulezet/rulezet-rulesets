rule Virus_Hijack_Trojan_GenericKDZ_98113_121 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_121.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c392a96a16948889ebd618dbf7a841d0ea9b417fd496c142e69ba1b057e24551"

  strings:
    $s1 = "tyour order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}