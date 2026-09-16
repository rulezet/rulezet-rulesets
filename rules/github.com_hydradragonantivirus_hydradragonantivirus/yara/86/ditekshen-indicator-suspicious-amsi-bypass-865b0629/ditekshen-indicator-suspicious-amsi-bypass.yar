rule DITEKSHEN_INDICATOR_SUSPICIOUS_AMSI_Bypass: FILE {
  meta:
    description = "Detects AMSI bypass pattern"
    author      = "ditekSHen"
    id          = "cdb457b3-1f41-5f58-a482-a00d269c1293"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L778-L791"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "b398c20a0e7b2dff5fab87575c555b657749d7c3b3e8f1a0f99db7e8f669e3ce"
    score       = 40
    quality     = 45
    tags        = "FILE"
    importance  = 20

  strings:
    $v1_1 = "[Ref].Assembly.GetType(" ascii nocase
    $v1_2 = "System.Management.Automation.AmsiUtils" ascii
    $v1_3 = "GetField(" ascii nocase
    $v1_4 = "amsiInitFailed" ascii
    $v1_5 = "NonPublic,Static" ascii
    $v1_6 = "SetValue(" ascii nocase

  condition:
    5 of them and filesize < 2000KB
}