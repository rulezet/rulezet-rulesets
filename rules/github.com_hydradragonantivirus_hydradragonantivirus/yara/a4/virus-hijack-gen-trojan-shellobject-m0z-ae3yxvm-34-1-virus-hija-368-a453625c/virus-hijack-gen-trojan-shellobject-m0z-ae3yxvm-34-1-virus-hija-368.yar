import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_34_1_Virus_Hija_368 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_34_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_35_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_36_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_37_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e3e00075143d3fd621479fb61188c41560186ce1877e83e9d1e938b866adef6"
    hash2       = "37766ff8af0d6cd5ff8df2eb44dcb1ef21f3f2534d3b295833f0fa4346d0769c"
    hash3       = "427b6129f42722d768ebf07bcd966939120313f08e3c5b0c857644f6c2a51693"
    hash4       = "b6c03a67716ee57c51bb9b400fe294f2fdc3e996ec1afdeeb820553796c00c31"

  strings:
    $s1  = "start {0}bin_tools\\baretail\\baretail.exe {0}logs\\access.log {0}logs\\error.log" fullword wide
    $s2  = "Monitor running processes count" fullword wide
    $s3  = "<script>function s(){window.scrollTo(0,document.body.scrollHeight);}</script><pre style=\"font-size:11px\">" fullword wide
    $s4  = "Version 0.8.0.8" fullword wide
    $s5  = " - Openresty Tool" fullword wide
    $s6  = "WinWatcher - {0} changes in {1} [recursive:{2}]" fullword wide
    $s7  = "Error creating log file." fullword wide
    $s8  = "Error writing log file." fullword wide
    $s9  = "nginx -s quit" fullword wide
    $s10 = "<script>s();</script>" fullword wide
    $s11 = "Write also in logfile (saved in exe working directory)" fullword wide
    $s12 = "Log window auto scrolling" fullword wide
    $s13 = "ERROR: Buffer Overflow !" fullword wide
    $s14 = " ERROR: Buffer Overflow!" fullword wide
    $s15 = "\" align=absmiddle /> ERROR BO! " fullword wide
    $s16 = " ERROR ex: " fullword wide
    $s17 = "System directory" fullword wide
    $s18 = "User directory" fullword wide
    $s19 = "include subdirectories" fullword wide
    $s20 = "Openresty Tool for win" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (8 of them)
    ) or (all of them)
}