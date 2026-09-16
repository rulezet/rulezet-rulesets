rule Virus_Hijack_GenPack_Backdoor_Hangup_B_467_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_467_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99f37d7e3bfd21a2c80919ccd8fb5e788681dc1b92fc578ded3b6eb61ab7ffad"

  strings:
    $s1  = "process \"%s\", take %f seconds." fullword wide
    $s2  = "Processing Finish, take %f seconds." fullword wide
    $s3  = ".?AV?$VectorRvaVisitor@V?$unique_ptr@VTypedRVA@DisassemblerElf32@courgette@@U?$default_delete@VTypedRVA@DisassemblerElf32@courge" ascii
    $s4  = ")Zhuhai Kingsoft Office Software Co., Ltd.1200" fullword ascii
    $s5  = ")Zhuhai Kingsoft Office Software Co., Ltd.0" fullword ascii
    $s6  = "All Files are Correct! Verify OK!" fullword ascii
    $s7  = "2023 Kingsoft Corporation. All rights reserved." fullword wide
    $s8  = "The last File is Incorrect! Program teminated!" fullword ascii
    $s9  = ".?AVEnvironmentImpl@?A0x8cd352ff@base@@" fullword ascii
    $s10 = ".?AVEnvironment@base@@" fullword ascii
    $s11 = "Use Time: " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}