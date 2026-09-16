rule Trojan_Danger_Trojan_GenericKD_67166905_316 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_316.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d3822b01ee9a4451ef4fd3eb4631b815e853db89ad537dd6c639275324a9bfc"

  strings:
    $s1 = "Task Scheduler.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}