rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Uacbypass_Fodhelper {
  meta:
    description = "detects Windows exceutables potentially bypassing UAC using fodhelper.exe"
    author      = "ditekSHen"
    id          = "0651e428-a2ef-508d-ad89-c68ac758808f"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L1083-L1094"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "ec41ca2185732e418825f7c32095dea361a53e586e498baf4c17eaaf9602ba5e"
    score       = 40
    quality     = 43
    tags        = ""
    importance  = 20

  strings:
    $s1 = "\\software\\classes\\ms-settings\\shell\\open\\command" ascii wide nocase
    $s2 = "DelegateExecute" ascii wide
    $s3 = "fodhelper" ascii wide
    $s4 = "ConsentPromptBehaviorAdmin" ascii wide

  condition:
    all of them
}