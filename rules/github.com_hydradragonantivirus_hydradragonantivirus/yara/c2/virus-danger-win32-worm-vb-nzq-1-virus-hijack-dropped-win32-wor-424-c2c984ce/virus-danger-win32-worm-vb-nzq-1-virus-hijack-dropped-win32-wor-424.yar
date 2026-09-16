rule _Virus_Danger_Win32_Worm_VB_NZQ_1_Virus_Hijack_Dropped_Win32_Wor_424 {
  meta:
    description = "datamaliciousorder - from files Virus.Danger_Win32.Worm.VB.NZQ_1.vir, Virus.Hijack_Dropped.Win32.Worm.VB.NXJ_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aOGzovi_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_3_2.vir, VirusSharemodificationofWin32Virut56_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86501b6f1f138531408efabe39c58b5c8e5f00c20916a0aa803ab7578d2d8c9d"
    hash2       = "6eab816a4bcf7258e1b7ee52a7113aaa36abd6ad3ae7508c094aacf6cff19020"
    hash3       = "8d56821490b9b93e798df329a2917fa57d14ee271980476cf97cafd98a6c8181"
    hash4       = "cfd9bddfb49036ba9af08eaf5ecc80ee5ea3bcf0375e6f23f5991fa5fd81d8ae"
    hash5       = "f3d7caa0e4ee00e818ca3e8a1affd294becd36d702c18d299cc59d5ead253036"
    hash6       = "5c1fde39e4e958466eb2b9b9e4097175242889183d93a40761bb29503870ff5e"
    hash7       = "d6767a4b06185a363a0348866269fb91d958be7963fa9f901ec3f2503d418fef"
    hash8       = "3654887b24436e2aa3c9452a9e84447154e026d38f32bcc297a87206e1b40e2e"

  strings:
    $s1  = " NavigateURL Complete" fullword wide
    $s2  = "[PerfFreq=%7d/s  *-since start :-duration %2d%% buffer used]" fullword ascii
    $s3  = "!Error! Fatal error encountered. Results may be inaccurate." fullword ascii
    $s4  = "marslib module %s started" fullword wide
    $s5  = "[!Start Mars perf   Ver(%s)   %d:%02d:%02d   %d/%d/%02d ]" fullword ascii
    $s6  = "[Mars Perf Statistics  %d total  %d:%02d:%02d   %d/%d/%02d]" fullword ascii
    $s7  = "*note: average time doesn't include the MaxTime entry" fullword ascii
    $s8  = "[End Mars Perf Statistics]" fullword ascii
    $s9  = "Invalid Atom" fullword ascii
    $s10 = "MarsPerf shutdown" fullword wide
    $s11 = "[!Calculated durations follow:]" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}