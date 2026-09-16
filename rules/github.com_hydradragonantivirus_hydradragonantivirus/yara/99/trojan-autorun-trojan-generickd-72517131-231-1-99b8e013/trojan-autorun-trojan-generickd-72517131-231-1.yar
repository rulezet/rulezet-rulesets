rule Trojan_Autorun_Trojan_GenericKD_72517131_231_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_231_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e9e522c0197e9b05c93a53d7e686cb118e27d3a3b8cc99a16d9f1ce46a11a3f"

  strings:
    $s1 = "required and all actual users must be license" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}