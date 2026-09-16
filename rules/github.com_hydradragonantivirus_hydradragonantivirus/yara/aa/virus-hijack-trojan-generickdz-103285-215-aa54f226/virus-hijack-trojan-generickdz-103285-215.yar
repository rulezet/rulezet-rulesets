rule Virus_Hijack_Trojan_GenericKDZ_103285_215 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_215.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a1b86247d29c4e678bb8dd0953aba7029a357c50ce5a15d62a615bea4bae706"

  strings:
    $s1 = "&9policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}