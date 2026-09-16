rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_19_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_19_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03b40908c2b09c319a64ffe1ea994559133d48ddf5053436913f6585de4442c6"

  strings:
    $s1 = "*`pElt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}