rule Virus_Hijack_Trojan_GenericKDZ_98113_244_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_244_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8011dfaee42e176dd50cec5f911803e66ca9fcdce7da97bad5fed13ffad4afc"

  strings:
    $s1 = ";BOLk}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}