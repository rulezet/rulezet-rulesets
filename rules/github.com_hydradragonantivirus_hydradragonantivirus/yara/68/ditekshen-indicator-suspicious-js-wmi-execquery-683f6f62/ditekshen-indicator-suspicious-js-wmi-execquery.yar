rule DITEKSHEN_INDICATOR_SUSPICIOUS_JS_WMI_Execquery {
  meta:
    description = "Detects JS potentially executing WMI queries"
    author      = "ditekSHen"
    id          = "28f37b24-8bf3-5f5c-af47-dc6da5f6397a"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L1135-L1147"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "e5145aa3a7ce54cda84929f6806a1d7b1cb37db729bb932c5c76994fb683250e"
    score       = 40
    quality     = 45
    tags        = ""
    importance  = 20

  strings:
    $ex = ".ExecQuery(" ascii nocase
    $s1 = "GetObject(" ascii nocase
    $s2 = "String.fromCharCode(" ascii nocase
    $s3 = "ActiveXObject(" ascii nocase
    $s4 = ".Sleep(" ascii nocase

  condition:
    ($ex and all of ($s*))
}