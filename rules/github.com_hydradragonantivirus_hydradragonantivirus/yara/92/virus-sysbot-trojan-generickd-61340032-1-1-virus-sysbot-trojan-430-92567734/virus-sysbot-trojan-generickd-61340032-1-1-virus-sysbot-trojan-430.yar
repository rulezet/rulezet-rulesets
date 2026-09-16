rule _Virus_Sysbot_Trojan_GenericKD_61340032_1_1_Virus_Sysbot_Trojan__430 {
  meta:
    description = "datamaliciousorder - from files Virus.Sysbot_Trojan.GenericKD.61340032_1_1.vir, Virus.Sysbot_Trojan.GenericKD.61340032_2_1.vir, Virus.Sysbot_Trojan.GenericKD.64507427_1.vir, Virus.Sysbot_Trojan.GenericKD.70517336_1.vir, Virus.Sysbot_Trojan.GenericKD.70681719_1_1.vir, Virus.Sysbot_Trojan.GenericKD.70681719_2_1.vir, Virus.Sysbot_Trojan.GenericKD.70681719_3_1.vir, Virus.Sysbot_Trojan.GenericKD.70681719_4_1.vir, Virus.Sysbot_Trojan.GenericKD.70681719_5_1.vir, Virus.Sysbot_Trojan.GenericKD.70681719_6_1.vir, Virus.Sysbot_Trojan.GenericKD.70681719_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2230005741f2c766c4ce2d26b525f705a1ac1d65ebab1b3e03ca8808a4bc14f3"
    hash2       = "abdb9f01c83946668364bd1d280f361b65248d8ef0c7cd57b11f114e2bd1bc72"
    hash3       = "39724fa50de7a8937dec84a3f00fe23c9dea895d312bdce8133db18f15ee1a81"
    hash4       = "c32a271faa636531bcfac881e50f258457ba4779bb491eb043d9d2035da59559"
    hash5       = "5d14d6480c4d20dd420d598d6e7f503b7e714ce9d21d56cc73a2f2dbcb1100af"
    hash6       = "6a960e37ff5beea3980c33041e41aa328879d65ca177f0c424c34dd13b94ab79"
    hash7       = "73bc9db0d6ed275b95b4bf2c207f900c8e694b48a8bb2957630d9add87852db7"
    hash8       = "d443dbd070c2c9bfc89727fbba164ead77f562cf29f959762342807ca4f42704"
    hash9       = "0c2e690572d7a0a66dfaff96486f73d456b34c5a7e37cfacc74fceaff4db9c62"
    hash10      = "e25f8dfba5d8f067cac8a03e0fcd19371baa2b0f9d94faca758565b4d9015a89"
    hash11      = "1ed6054025bb1e38a0695d4aef88a8799144160ab3a09b115cba1cc70fcf6255"

  strings:
    $s1  = ": prev=%d cur=%d compute swapped -- untested" fullword ascii
    $s2  = ": prev=%d cur=%d gone back? -- untested" fullword ascii
    $s3  = "aborted coded: (%d=%d/%d+%d) > %d" fullword ascii
    $s4  = "lpbi != NULL && lpbi->biCompression == BI_RGB" fullword wide
    $s5  = "aborted absolute: (%d=%d/%d+%d) > %d" fullword ascii
    $s6  = "switched to keyframe, was small enough!" fullword ascii
    $s7  = "lpIn != NULL && lpOut != NULL" fullword wide
    $s8  = "pi != NULL && lpbiOut != NULL" fullword wide
    $s9  = "pi != NULL && lpbiIn != NULL && lpIn != NULL" fullword wide
    $s10 = "pi->pPrevFrame != NULL" fullword wide
    $s11 = "pi->pCurFrame != NULL" fullword wide
    $s12 = "lpA && lpB && lDist >= 0 && width > 0" fullword wide
    $s13 = "(...) -> SetPalette(%p,%p,%p): stub!" fullword ascii
    $s14 = "Unknown message uMsg=0x%08X lParam1=0x%08lX lParam2=0x%08lX" fullword ascii
    $s15 = "clrs != NULL" fullword wide
    $s16 = "lpbi != NULL" fullword wide
    $s17 = "count <= 2" fullword wide
    $s18 = "jumpy > 0" fullword wide
    $s19 = "cannot compress and decompress at same time!" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}