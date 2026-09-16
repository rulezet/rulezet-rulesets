rule sig_20161206_32b89501cacbd7d37488d695e1a81b22 {
  meta:
    description = "datamaliciousorder - file 20161206_32b89501cacbd7d37488d695e1a81b22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce09adbc297419592e2de7bb6bc73c6f175e3de35781449cb6f35e6ecb656200"

  strings:
    $s1 = "function _Bd6(s) {var _GIp8 = new Date();_GIp8.setUTCFullYear(\"2003\");if (_GIp8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Bd6(s) {var _GIp8 = new Date();_GIp8.setUTCFullYear(\"2003\");if (_GIp8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Be8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}