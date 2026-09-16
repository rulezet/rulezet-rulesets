rule Trojan_Danger_Trojan_GenericKD_72677122_192_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_192_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff482c962c62e07c0a3a898d831e05fe862d55645ffdf37e09c9a957db1e3b51"

  strings:
    $s1  = "Windows NT\\CurrentVersion\\Image File Execution Options\\%s" fullword wide
    $s2  = "/CREATE /SC ONLOGON /TN \"Windows Update Check - 0x%08X\" /TR \"%s\" /RL HIGHEST" fullword wide
    $s3  = "Image File Execution Options\\%s" fullword wide
    $s4  = "(BOT_INFO) Process [%u] EXE: %s | Threads = %u | pID = %u | POINTS: %lu" fullword wide
    $s5  = "(BOT) Process [%d] EXE: %s || Killing process!" fullword wide
    $s6  = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)" fullword ascii
    $s7  = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; WOW64; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.0.04506; Media Center PC 5.0; .N" ascii
    $s8  = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; WOW64; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.0.04506; Media Center PC 5.0; .N" ascii
    $s9  = "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.2; WOW64; .NET CLR 2.0.50726)" fullword ascii
    $s10 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; NeosBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)" fullword ascii
    $s11 = "%s\\FTP Commander Deluxe" fullword ascii
    $s12 = "%s\\FTP Commander" fullword ascii
    $s13 = "/C start /d. %s&\"%s\"" fullword wide
    $s14 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)" fullword ascii
    $s15 = "Mozilla/4.0 (compatible; MSIE 6.01; Windows NT 6.0)" fullword ascii
    $s16 = "Windows Update Service" fullword wide
    $s17 = "/DELETE /TN \"Windows Update Check - 0x%08X\" /F" fullword wide
    $s18 = "Windows NT Update Service" fullword wide
    $s19 = "/c start \"\" \"%s\" /%s \"%s\" " fullword wide
    $s20 = "Privilege Error" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}