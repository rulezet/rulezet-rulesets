rule Trojan_Danger_Trojan_GenericKD_72853156_322 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_322.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efa03e3f067f1399524790a322a4f2719bbf49294dfbd11fbdbad780ef6a8399"

  strings:
    $s1 = "4};JAzz" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}