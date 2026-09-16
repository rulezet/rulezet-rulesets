rule DITEKSHEN_INDICATOR_SUSPICIOUS_WMIC_Downloader: FILE {
  meta:
    description = "Detects files utilizing WMIC for whitelisting bypass and downloading second stage payloads"
    author      = "ditekSHen"
    id          = "bdd6deeb-9d43-55ef-9264-652044ba6938"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L765-L776"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "0c665f77659b57770f726297b64780764235ba0e72730c985eea62c116fe97e7"
    score       = 40
    quality     = 45
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "WMIC.exe os get /format:\"http" wide
    $s2 = "WMIC.exe computersystem get /format:\"http" wide
    $s3 = "WMIC.exe dcomapp get /format:\"http" wide
    $s4 = "WMIC.exe desktop get /format:\"http" wide

  condition:
    (uint16(0) == 0x004c or uint16(0) == 0x5a4d) and 1 of them
}