rule Virus_Hijack_Trojan_GenericKDZ_98113_65 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_65.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34a70560d0f1f82533f3c4452a51fefdfdf17a525451eec7febc4a622f1a2c2c"

  strings:
    $s1 = "TO RESOLVE A DISPUTE WITH THE MA NUFA CTURER OR INSTALLER, OR`" fullword ascii
    $s2 = "Joyour order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}