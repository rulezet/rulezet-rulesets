rule DITEKSHEN_INDICATOR_SUSPICIOUS_Finger_Download_Pattern {
  meta:
    description = "Detects files embedding and abusing the finger command for download"
    author      = "ditekSHen"
    id          = "6647b410-c8f0-596b-95d7-dbc6a951a83f"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L1108-L1118"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "04cbb1abc4c3d2990bae798ece052eb8aa1b5104b5712e98aeb80731316b9c57"
    score       = 40
    quality     = 45
    tags        = ""
    importance  = 20

  strings:
    $pat1 = /finger(\.exe)?\s.{1,50}@.{7,10}\|/ ascii wide
    $pat2 = "-Command \"finger" ascii wide
    $ne1  = "Nmap service detection probe list" ascii

  condition:
    not any of ($ne*) and any of ($pat*)
}