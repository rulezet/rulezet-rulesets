rule Virus_Hijack_GenPack_Backdoor_Hangup_B_47_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_47_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d57d08fa31e2973d63daeb9f64a7e76891c94bc032cd176fa2e90bfeeee93afc"

  strings:
    $x1  = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii
    $s2  = "Module path: e:\\syzygy_wpsoptimize\\original\\et.exe" fullword ascii
    $s3  = "WPS Cloud Service - " fullword wide
    $s4  = "No Process!" fullword wide
    $s5  = "Toolchain version: 0.8.33.0 (0000000)" fullword ascii
    $s6  = "cutionLevel></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"> " fullword ascii
    $s7  = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Kingsoft Office" fullword wide
    $s8  = "WPS Office Cloud Service" fullword wide
    $s9  = ")Zhuhai Kingsoft Office Software Co., Ltd.1200" fullword ascii
    $s10 = ")Zhuhai Kingsoft Office Software Co., Ltd.0" fullword ascii
    $s11 = "Zhuhai Kingsoft Office Software Co., Ltd." fullword wide
    $s12 = "1988-2018 Kingsoft Corporation. All rights reserved." fullword wide
    $s13 = "Creation time: Mon, 06 Jul 2020 00:13:17 GMT" fullword ascii
    $s14 = "KINGSOFT JAPAN, INC." fullword wide
    $s15 = "!This is a Windows program, you cannot run it in DOS.\\r\\n$3c.A3c.A3PE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}