rule _Virus_Autorun_Dropped_Win32_Worm_VB_NXJ_Virus_Autorun_Dropped_W_400 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Dropped.Win32.Worm.VB.NXJ.vir, Virus.Autorun_Dropped.Win32.Worm.VB.NXJ_1.vir, Virus.Danger_Win32.Worm.VB.NZQ_1.vir, Virus.Hijack_Dropped.Win32.Worm.VB.NXJ_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@amgke!k_20_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqsS8zj_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b79a57a926f801baca06e13180644ff8a9531494ec2bc0fb219ba35b9e51f5"
    hash2       = "0b5dc186b2c779853a25d3f0d3bc3470a319fb2d976594e000f7f06c23b18e03"
    hash3       = "86501b6f1f138531408efabe39c58b5c8e5f00c20916a0aa803ab7578d2d8c9d"
    hash4       = "6eab816a4bcf7258e1b7ee52a7113aaa36abd6ad3ae7508c094aacf6cff19020"
    hash5       = "b00888b91be353d18e18c45d23c3967d666971a1f717bd02a9e9850292d73f39"
    hash6       = "0ddd2c9145afaab6ae9d694619759a4d6569ae9345c64061e81160a1d2b93def"
    hash7       = "d6767a4b06185a363a0348866269fb91d958be7963fa9f901ec3f2503d418fef"
    hash8       = "4e62e7a3b77d4d0abb803c175f51d1242fda33bfd3308991b9e90391cac1c369"

  strings:
    $s1 = "MSN Messenger Service" fullword ascii
    $s2 = "Opens the %s window." fullword ascii
    $s3 = "Default Visible" fullword ascii
    $s4 = "Rich!2V" fullword ascii
    $s5 = "Windows Messenger" fullword ascii
    $s6 = "; Overwritten by install " fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}