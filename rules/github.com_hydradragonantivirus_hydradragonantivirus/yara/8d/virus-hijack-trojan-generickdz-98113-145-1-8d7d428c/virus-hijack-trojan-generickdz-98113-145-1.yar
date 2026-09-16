rule Virus_Hijack_Trojan_GenericKDZ_98113_145_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_145_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fd90d6670b995eb98e4e11802cc25ebd4e0f9e5d7f735435b039095a34a1f85"

  strings:
    $s1 = "U&tahR" fullword ascii
    $s2 = "W}mOaT" fullword ascii
    $s3 = "!&koff" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}