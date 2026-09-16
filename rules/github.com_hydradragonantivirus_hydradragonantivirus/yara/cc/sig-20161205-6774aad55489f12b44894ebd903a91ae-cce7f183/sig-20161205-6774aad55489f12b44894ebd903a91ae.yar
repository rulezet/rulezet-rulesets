rule sig_20161205_6774aad55489f12b44894ebd903a91ae {
  meta:
    description = "datamaliciousorder - file 20161205_6774aad55489f12b44894ebd903a91ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "184022979c1d575960b53064884e783a4cda77a1f3923adb8cf07ead08cf2e7f"

  strings:
    $s1 = "function _Eo9(s) {var _VHg8 = new Date();_VHg8.setUTCFullYear(\"2003\");if (_VHg8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Eo9(s) {var _VHg8 = new Date();_VHg8.setUTCFullYear(\"2003\");if (_VHg8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Td6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}