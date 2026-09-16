rule sig_20161206_cdbc0e87ae70271b14c7bec62dd1dc01 {
  meta:
    description = "datamaliciousorder - file 20161206_cdbc0e87ae70271b14c7bec62dd1dc01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec4e487f660bbb1fc6ea6a00f22a17a83fbb0878d90badbda5e8024341c9d60c"

  strings:
    $s1 = "function _On6(s) {var _Ye5 = new Date();_Ye5.setUTCFullYear(\"2003\");if (_Ye5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _On6(s) {var _Ye5 = new Date();_Ye5.setUTCFullYear(\"2003\");if (_Ye5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _JUj5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}