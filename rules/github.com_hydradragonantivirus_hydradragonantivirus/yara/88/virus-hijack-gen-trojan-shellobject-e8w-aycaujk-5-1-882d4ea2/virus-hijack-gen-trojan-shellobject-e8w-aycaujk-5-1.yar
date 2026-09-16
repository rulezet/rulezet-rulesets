rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8371cb061e003a12e8dfa09c44aecf2b17f88e56c57e64aa1d7e73f146317e2"

  strings:
    $s1  = "%AppData% - Very Fast" fullword wide
    $s2  = "%UsersFolder% - Fast" fullword wide
    $s3  = "%SystemDrive% - Slow" fullword wide
    $s4  = "Profile URL: https://steamcommunity.com/profiles/" fullword wide
    $s5  = "Plugin couldn't process this action!" fullword wide
    $s6  = "Select * From Win32_ComputerSystem" fullword wide
    $s7  = "notepad.exe & pause" fullword wide
    $s8  = "Other/Discord Token(s).txt" fullword wide
    $s9  = ".NET Framework Version 4.X is not detected." fullword wide
    $s10 = "POST / HTTP/1.1" fullword wide
    $s11 = "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Saf" wide
    $s12 = "Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safar" wide
    $s13 = "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.34 (KHTML, like Gecko) Version/11.0 Mobile/15A5341f Saf" wide
    $s14 = "Mozilla/5.0 (iPhone9,4; U; CPU iPhone OS 10_0_1 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A4" wide
    $s15 = "] Temp DB: " fullword wide
    $s16 = "[Other] Grabbing discord tokens" fullword wide
    $s17 = "no tokens found in string" fullword wide
    $s18 = " already exists in the table" fullword wide
    $s19 = "[Browsers] Scanning directory (" fullword wide
    $s20 = "Scanning directory (" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}