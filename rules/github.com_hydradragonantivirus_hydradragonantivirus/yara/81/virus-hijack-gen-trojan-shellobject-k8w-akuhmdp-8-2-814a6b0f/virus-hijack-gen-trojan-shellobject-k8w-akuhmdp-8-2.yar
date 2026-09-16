rule Virus_Hijack_Gen_Trojan_ShellObject_k8W_aKuHmDp_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8W@aKuHmDp_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b31bd9eb860f4074ce3f85303c25a017c33681592fb0317c12db78c99b41df16"

  strings:
    $s1 = "uCD?LiPA@\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}