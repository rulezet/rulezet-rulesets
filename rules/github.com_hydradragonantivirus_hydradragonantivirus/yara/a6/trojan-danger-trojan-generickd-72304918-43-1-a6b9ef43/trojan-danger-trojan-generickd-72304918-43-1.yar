rule Trojan_Danger_Trojan_GenericKD_72304918_43_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_43_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfd09e446dfd120c3e72a7653c7cdf43cdd78a26daa7cd698cb71f3b82f39eb5"

  strings:
    $s1 = "OUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}