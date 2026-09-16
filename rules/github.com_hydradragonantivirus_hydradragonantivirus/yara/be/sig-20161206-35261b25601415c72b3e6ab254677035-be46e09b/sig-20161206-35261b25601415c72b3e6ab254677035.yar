rule sig_20161206_35261b25601415c72b3e6ab254677035 {
  meta:
    description = "datamaliciousorder - file 20161206_35261b25601415c72b3e6ab254677035.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8b08d82d0b9ebd1ddc744114191c02d2c70ccd4e6ae80ef02acac921a7e7228"

  strings:
    $s1 = "function _Vn2(s) {var _Ud5 = new Date();_Ud5.setUTCFullYear(\"2003\");if (_Ud5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Vn2(s) {var _Ud5 = new Date();_Ud5.setUTCFullYear(\"2003\");if (_Ud5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _LWt3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}