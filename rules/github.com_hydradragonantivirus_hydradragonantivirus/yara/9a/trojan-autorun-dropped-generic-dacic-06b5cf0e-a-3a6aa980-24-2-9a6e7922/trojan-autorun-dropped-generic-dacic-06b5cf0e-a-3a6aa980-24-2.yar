rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_24_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_24_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d14cc88a5ce1fd079243253041396a6c78c7f4b44957e69c80f38d20da70722d"

  strings:
    $s1  = "dummy::login_form" fullword wide
    $s2  = "form::login_form" fullword wide
    $s3  = "Password:B" fullword ascii
    $s4  = "EAn administrative password is required to exit." fullword ascii
    $s5  = "Possession" fullword ascii
    $s6  = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.103 Safari/537.36" fullword wide
    $s7  = "Are you sure that you want to log out now?" fullword wide
    $s8  = "Confirm Logoff" fullword wide
    $s9  = "<Possession>k__BackingField" fullword ascii
    $s10 = "Scraping CBS: " fullword wide
    $s11 = "Scraping Pinnacle: " fullword wide
    $s12 = "Scraping NFL: " fullword wide
    $s13 = "ERROR: Settings file is broken" fullword wide
    $s14 = "NOTICE: Your session is time limited, please pay attention to the time remaining." fullword wide
    $s15 = "You will be signed out at the conclusion of your session." fullword wide
    $s16 = "<Scrape>b__14_1" fullword ascii
    $s17 = "<Quarter>k__BackingField" fullword ascii
    $s18 = "<Away>k__BackingField" fullword ascii
    $s19 = "<Scrape>b__14_0" fullword ascii
    $s20 = "Please enter it below" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}