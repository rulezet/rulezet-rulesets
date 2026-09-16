rule Trojan_Autorun_Trojan_GenericKDZ_94847_420_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_420_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22399c31f90019843554c22991ec9b1edd668dba862b5659444a4e38f697dad2"

  strings:
    $s1 = "4you received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}