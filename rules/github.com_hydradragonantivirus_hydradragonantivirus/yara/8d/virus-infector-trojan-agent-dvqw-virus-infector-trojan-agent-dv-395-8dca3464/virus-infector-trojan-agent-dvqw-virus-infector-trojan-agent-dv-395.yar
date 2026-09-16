import "pe"
rule _Virus_Infector_Trojan_Agent_DVQW_Virus_Infector_Trojan_Agent_DV_395 {
  meta:
    description = "datamaliciousorder - from files Virus.Infector_Trojan.Agent.DVQW.vir, Virus.Infector_Trojan.Agent.DVQW_1.vir, Virus.Infector_Trojan.Agent.DVQW_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a304e032c6c319141465adfd06d9312f636cd803459406b10d9a97cf27c75e02"
    hash2       = "4b8cfca15d714f6360323969a14b30d80c1b86959b3d83ec2d3e9b1a7055d1ae"
    hash3       = "9a7c4bda0ec41f0901406a9047f9ca978c5bbf26ed6b2a5a6921213a99a20ca0"

  strings:
    $x1 = "reg add \"hklm\\software\\microsoft\\windows nt\\currentversion\\Image File Execution Options\\ZhuDongFangYu.exe\" /v debugger /" ascii
    $x2 = "reg add \"hklm\\software\\microsoft\\windows nt\\currentversion\\Image File Execution Options\\360tray.exe\" /v debugger /t reg_" ascii
    $x3 = "reg add \"hklm\\software\\microsoft\\windows nt\\currentversion\\Image File Execution Options\\360tray.exe\" /v debugger /t reg_" ascii
    $x4 = "reg add \"hklm\\software\\microsoft\\windows nt\\currentversion\\Image File Execution Options\\taskmgr.exe\" /v debugger /t reg_" ascii
    $x5 = "reg add \"hklm\\software\\microsoft\\windows nt\\currentversion\\Image File Execution Options\\ZhuDongFangYu.exe\" /v debugger /" ascii
    $x6 = "reg add \"hklm\\software\\microsoft\\windows nt\\currentversion\\Image File Execution Options\\taskmgr.exe\" /v debugger /t reg_" ascii
    $s7 = "virus QQ 621370902" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d2bf2bc66c5e49a85254cd29b19046bd" and (1 of ($x*) and all of them)
    ) or (all of them)
}