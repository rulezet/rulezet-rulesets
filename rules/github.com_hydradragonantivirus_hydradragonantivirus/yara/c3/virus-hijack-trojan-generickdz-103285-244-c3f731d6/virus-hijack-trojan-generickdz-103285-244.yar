rule Virus_Hijack_Trojan_GenericKDZ_103285_244 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_244.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73eab90c12f77a6e7e0c6468a042b7c28f72dfe1f8bc334733b7c2461ee795fa"

  strings:
    $s1 = "rF$ =\\%`pC0.%Plew" fullword ascii
    $s2 = "vCallbackListToRpc: begin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}