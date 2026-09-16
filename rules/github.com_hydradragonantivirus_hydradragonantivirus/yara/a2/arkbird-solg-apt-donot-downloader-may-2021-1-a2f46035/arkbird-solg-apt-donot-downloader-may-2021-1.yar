rule ARKBIRD_SOLG_APT_Donot_Downloader_May_2021_1: FILE {
  meta:
    description = "Detect the trojan downloader used by Donot group"
    author      = "Arkbird_SOLG"
    id          = "251a809e-9e36-5c46-955f-006531bd9619"
    date        = "2020-05-09"
    modified    = "2021-05-09"
    reference   = "Internal Research"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-05-09/Donot/APT_Donot_Downloader_May_2021_1.yara#L1-L20"
    license_url = "N/A"
    logic_hash  = "df64ab97b74935ce8b73c3854eb81fa1dbd4e59b1e27c43ae9c85b90aaaef6f7"
    score       = 75
    quality     = 75
    tags        = "FILE"
    hash1       = "28aa296bda12f0184564c5f6b46e679f07255aa8df58b861ea17910cdcaa674a"
    hash2       = "03730cdc23a3d10c8752ad1464ff2e68a64c69f8310b0ceea4d52b1db0215dfc"
    hash3       = "edd590c343570f7576aca83da58967e058585c6ba861682dca2fc987c713ee3a"
    tlp         = "White"
    adversary   = "Donot"

  strings:
    $seq1 = "echo off\n md %s \n md %s \n md %s \n md %s \n md %s \n  attrib +a +h +s %s \n attrib +a +h +s %s \n attrib +a +h +s %s \n attrib +a +h +s %s \n del /f %s \n SET /A %%COMPUTERNAME%% \n SET /A RAND=%%RANDOM%% 10000 + 2 \n echo %%COMPUTERNAME%%-%%RAND%% >> %s \n schtasks /delete /tn MobUpdate /f  \n schtasks /delete /tn TaskUpdate /f \n schtasks /delete /tn MachineCore /f \n schtasks /create /sc minute /mo 20 /f /tn TaskUpdate /tr %s  \n schtasks /create /sc minute /mo 10 /f /tn MachineCore /tr %s \n move %%APPDATA%"
    $seq2 = { c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 ?? 42 [2] e8 ?? 01 00 00 83 ec 14 [0-3] c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 [2-5] 24 04 [0-3] 89 04 24 e8 ?? 01 00 00 83 ec 18 89 [1-9] c7 44 24 04 ?? 43 [2] c7 04 24 ?? 61 [2] e8 ?? 08 00 00 }
    $s1   = "VirtualQuery failed for %d bytes at address %p" fullword ascii
    $s2   = { 25 73 5c [1-14] 2e 62 61 74 }
    $s3   = { 25 73 5c [1-14] 25 }

  condition:
    uint16(0) == 0x5a4d and filesize > 10KB and all of ($seq*) and 2 of ($s*)
}