rule sig_20161206_0b15310dca3e625fa5072abaa45e567d {
  meta:
    description = "datamaliciousorder - file 20161206_0b15310dca3e625fa5072abaa45e567d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b25afaf517d0ae35240a46603ea65c279b804470236d3cd62ed1593c2cf091c7"

  strings:
    $s1 = "function _SWl6(s) {var _OId5 = new Date();_OId5.setUTCFullYear(\"2003\");if (_OId5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _SWl6(s) {var _OId5 = new Date();_OId5.setUTCFullYear(\"2003\");if (_OId5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _BQm8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}