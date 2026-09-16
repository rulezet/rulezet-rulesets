rule Trojan_Autorun_Trojan_GenericKD_47942535 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.47942535.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd21ecce88a32ed01588c4dbb2a6504e0edff0b6143b4c322045b280c0b35764"

  strings:
    $s1 = "Arrays::ARR<unsigned char>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}