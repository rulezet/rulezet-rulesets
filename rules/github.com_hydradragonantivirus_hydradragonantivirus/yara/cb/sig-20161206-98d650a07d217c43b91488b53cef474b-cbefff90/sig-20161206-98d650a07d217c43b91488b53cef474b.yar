rule sig_20161206_98d650a07d217c43b91488b53cef474b {
  meta:
    description = "datamaliciousorder - file 20161206_98d650a07d217c43b91488b53cef474b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1637593defd52e9733e26969435d4c3731faf68874c7bdad45d5472141ac1ab"

  strings:
    $s1 = "function _Zh4(s) {var _BIo7 = new Date();_BIo7.setUTCFullYear(\"2003\");if (_BIo7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Zh4(s) {var _BIo7 = new Date();_BIo7.setUTCFullYear(\"2003\");if (_BIo7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _DHo8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}