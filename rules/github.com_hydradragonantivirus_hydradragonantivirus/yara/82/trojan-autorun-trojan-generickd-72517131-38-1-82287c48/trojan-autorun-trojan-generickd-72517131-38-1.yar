rule Trojan_Autorun_Trojan_GenericKD_72517131_38_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_38_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50ae3acb4c032b9a43b1bfaa58a117ec0657e91a626c94f5ace7d7005b64f425"

  strings:
    $s1 = "ujUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}