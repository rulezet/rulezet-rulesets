rule Trojan_Autorun_Trojan_GenericKD_72445520_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72445520_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "444eb4e0de0e9d343eba392b6073e71d0b2e484316e7ab85a5a607a0a2033c7c"

  strings:
    $s1 = "QTyour order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}