rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Uacbypass_Eventviewer: FILE {
  meta:
    description = "detects Windows exceutables potentially bypassing UAC using eventvwr.exe"
    author      = "ditekSHen"
    id          = "e4e82d5a-a524-5fac-b14c-4e53a95f4f2c"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L68-L77"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "4b893db727ea3ef07805058e9a93664dc01590f249158d9b825cc9cece935640"
    score       = 40
    quality     = 41
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "\\Classes\\mscfile\\shell\\open\\command" ascii wide nocase
    $s2 = "eventvwr.exe" ascii wide nocase

  condition:
    uint16(0) == 0x5a4d and all of them
}