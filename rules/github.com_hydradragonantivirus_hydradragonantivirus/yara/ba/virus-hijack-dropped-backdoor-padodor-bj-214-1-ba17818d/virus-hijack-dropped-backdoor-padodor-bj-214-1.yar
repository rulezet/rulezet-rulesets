rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_214_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_214_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "578fb87dccdd24d109df82e5a34d715710ea6fe4e5510a4272bf69cfa004c685"

  strings:
    $s1 = "7-Zip 19.00 (x64) is uninstalled" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}