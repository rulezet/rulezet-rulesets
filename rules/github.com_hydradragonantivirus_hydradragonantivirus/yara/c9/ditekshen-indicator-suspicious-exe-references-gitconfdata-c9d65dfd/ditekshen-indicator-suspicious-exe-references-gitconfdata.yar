rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_References_Gitconfdata: FILE {
  meta:
    description = "Detects executables referencing potentially confidential GIT artifacts. Observed in infostealer"
    author      = "ditekSHen"
    id          = "5462491b-f1cf-55ae-b120-ed09eb9549bc"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L2113-L2125"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "d8b370ea31fade4f6f4ae12903e40026d806862f6c4a7b5818e3942b6b849fd2"
    score       = 40
    quality     = 41
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "GithubDesktop\\Local Storage" ascii wide nocase
    $s2 = "GitHub Desktop\\Local Storage" ascii wide nocase
    $s3 = ".git-credentials" ascii wide
    $s4 = ".config\\git\\credentials" ascii wide
    $s5 = ".gitconfig" ascii wide

  condition:
    uint16(0) == 0x5a4d and 4 of them
}