rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_128_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_128_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee4b665f59e10a838d2f2b3f42cdba64539f0c078350669cbf7b6fea63eff2e0"

  strings:
    $s1 = "usage: DrvSrvInstaller.exe <driver_path> <service_name>" fullword ascii
    $s2 = "Start Service failed: %d" fullword ascii
    $s3 = "Service started!" fullword ascii
    $s4 = "Service created!" fullword ascii
    $s5 = "Service already exists.." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}