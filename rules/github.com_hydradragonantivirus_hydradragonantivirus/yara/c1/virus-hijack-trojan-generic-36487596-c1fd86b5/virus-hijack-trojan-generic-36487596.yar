rule Virus_Hijack_Trojan_Generic_36487596 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Generic.36487596.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afe0d14704ca5dc8039b71635613d50d1140353a113e004c31c5b379007e4354"

  strings:
    $s1 = "CoRk%\\M" fullword ascii
    $s2 = "c@Raki" fullword ascii
    $s3 = " quad<o" fullword ascii
    $s4 = "fY&;yAwL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}