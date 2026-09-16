rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aKrr_2b_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aKrr!2b_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0840a6cbaea7f938d66eba772c8dc05652659b48ec87472cedad54e42b18425"

  strings:
    $s1  = "arcavir avast avg avira bkav bullguard emsisoft anti-malware eset nod32 f-prot f-secure gdata ikarus k7 kaspersky lavasoft adawa" wide
    $s2  = "software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" fullword wide
    $s3  = "software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" fullword wide
    $s4  = "\" -CHECK & PING -n 2 127.0.0.1 & Exit" fullword wide
    $s5  = " Windows has detected a recent software change and needs permissions to continue. This process will take about 30-60 seconds dep" wide
    $s6  = "SELECT name FROM Win32_Processor" fullword wide
    $s7  = "|||Operating System: " fullword wide
    $s8  = "schtasks /create /sc minute /mo 1 /tn MicrosoftNt /tr " fullword wide
    $s9  = "%ERROR%" fullword wide
    $s10 = "bestanden door Windows te laten herstellen om dataverlies te voorkomen." fullword wide
    $s11 = "More details about this error" fullword wide
    $s12 = "Restore files and check disk for errors" fullword wide
    $s13 = "System Info:" fullword wide
    $s14 = "Error critico del disco duro" fullword wide
    $s15 = "The file or directory is corrupted and unreadable" fullword wide
    $s16 = "ado y no se puede leer" fullword wide
    $s17 = "browse " fullword wide
    $s18 = "%TEXT%" fullword wide
    $s19 = "/k START \"\" \"" fullword wide
    $s20 = "No Antivirus" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}