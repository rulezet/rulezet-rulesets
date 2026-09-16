rule NCSC_Sparrowdoor_Strings {
  meta:
    description = "Strings that appear in SparrowDoor’s backdoor. Targeting in memory."
    author      = "NCSC"
    id          = "6f96a577-fb59-57db-a66a-f514ecfbf982"
    date        = "2022-02-28"
    modified    = "2022-07-06"
    reference   = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
    source_url  = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/SparrowDoor_strings.yar#L1-L23"
    license_url = "N/A"
    logic_hash  = "65ec5d266ecd81ab8e4cfbcb352173f825bdae92fd4737b577cb209bace2a943"
    score       = 75
    quality     = 80
    tags        = ""
    hash1       = "c1890a6447c991880467b86a013dbeaa66cc615f"

  strings:
    $reg          = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
    $http_headers = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 5.0)\r\nAccept-Language: en-US\r\nAccept: */*\r\n"
    $http_proxy   = "HTTPS=HTTPS://%s:%d" ascii
    $debug        = "SeDebugPrivilege" ascii
    $av1          = "avp.exe" ascii
    $av2          = "ZhuDongFangYu.exe" ascii
    $av3          = "egui.exe" ascii
    $av4          = "TMBMSRV.exe" ascii
    $av5          = "ccSetMgr.exe" ascii
    $clipshot     = "clipshot" ascii
    $ComSpec      = "ComSpec" ascii
    $export       = "curl_easy_init" ascii

  condition:
    10 of them
}