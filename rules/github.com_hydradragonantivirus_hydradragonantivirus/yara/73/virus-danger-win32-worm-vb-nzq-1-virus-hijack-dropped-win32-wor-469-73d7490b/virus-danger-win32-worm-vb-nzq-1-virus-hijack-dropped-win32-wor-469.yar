rule _Virus_Danger_Win32_Worm_VB_NZQ_1_Virus_Hijack_Dropped_Win32_Wor_469 {
  meta:
    description = "datamaliciousorder - from files Virus.Danger_Win32.Worm.VB.NZQ_1.vir, Virus.Hijack_Dropped.Win32.Worm.VB.NXJ.vir, Virus.Hijack_Dropped.Win32.Worm.VB.NXJ_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@amgke!k_20_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_3_2.vir, Virus.Hooker_Trojan.GenericKD.64731121.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86501b6f1f138531408efabe39c58b5c8e5f00c20916a0aa803ab7578d2d8c9d"
    hash2       = "b4f34a5139502cad69b5c7d3138ff4d527894013f5a5471e176019ec675490bf"
    hash3       = "6eab816a4bcf7258e1b7ee52a7113aaa36abd6ad3ae7508c094aacf6cff19020"
    hash4       = "b00888b91be353d18e18c45d23c3967d666971a1f717bd02a9e9850292d73f39"
    hash5       = "d38ed19cfb2457a7b7ad16624740f7634a10d27be7b9f4d2bdcfa1cd81064139"
    hash6       = "bc0068b0dd00d800c6a777227a1aecddb53b886ed33ee9b6b5694b0edbcb4c31"
    hash7       = "9633d4cd7b4f96fbe5e897823eecfe25c6f8b221ac7606874f8112c0c5229127"

  strings:
    $s1 = "n no es compatible con este sistema operativo. El programa de instalaci" fullword wide
    $s2 = "me d'exploitation.  L'installation se termine ici." fullword wide
    $s3 = " supportato da questa installazione. Il programma di installazione verr" fullword wide
    $s4 = "ds inte av denna installation. Installationsprogrammet kommer nu att avslutas." fullword wide
    $s5 = "tzt.  Setup wird nun beendet." fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}