rule Trojan_Danger_Trojan_GenericKD_72853156_593 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_593.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18ec05c28db90e96edff18b0a7f91696b64f20971097fc4655e7182b9a74a46a"

  strings:
    $s1 = "SACK.@C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}