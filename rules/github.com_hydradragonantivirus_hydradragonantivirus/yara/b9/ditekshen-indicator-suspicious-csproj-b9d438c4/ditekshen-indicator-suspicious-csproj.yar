rule DITEKSHEN_INDICATOR_SUSPICIOUS_CSPROJ: FILE {
  meta:
    description = "Detects suspicious .CSPROJ files then compiled with msbuild"
    author      = "ditekSHen"
    id          = "99f9fbd0-9435-511a-b9f5-7ea11e655b79"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L1556-L1568"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "e41c82ab0da47192463f76192ea7748dfcf59193475871daf1a7a4ff2fda4d52"
    score       = 40
    quality     = 45
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "ToolsVersion=" ascii
    $s2 = "/developer/msbuild/" ascii
    $x1 = "[DllImport(\"\\x" ascii
    $x2 = "VirtualAlloc(" ascii nocase
    $x3 = "CallWindowProc(" ascii nocase

  condition:
    uint32(0) == 0x6f72503c and (all of ($s*) and 2 of ($x*))
}