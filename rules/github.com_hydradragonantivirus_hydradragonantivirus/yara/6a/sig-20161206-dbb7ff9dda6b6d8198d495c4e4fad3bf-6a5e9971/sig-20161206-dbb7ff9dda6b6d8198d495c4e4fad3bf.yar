rule sig_20161206_dbb7ff9dda6b6d8198d495c4e4fad3bf {
  meta:
    description = "datamaliciousorder - file 20161206_dbb7ff9dda6b6d8198d495c4e4fad3bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c63e175d6d34847b1628ba1d92c5e619bcd025dac7200f3c7951a8c71d993ff8"

  strings:
    $s1 = "function _YCp1(s) {var _Ne1 = new Date();_Ne1.setUTCFullYear(\"2003\");if (_Ne1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _YCp1(s) {var _Ne1 = new Date();_Ne1.setUTCFullYear(\"2003\");if (_Ne1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _FCb1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}