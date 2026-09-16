rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9cb6d5655d0998a545c540d8222579c61aee4099ce214a149b44d02120cdc8a"

  strings:
    $s1 = "vUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}