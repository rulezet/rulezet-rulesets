rule sig_20161205_01686ca8c7981bb80b6e759dda7ccf11 {
  meta:
    description = "datamaliciousorder - file 20161205_01686ca8c7981bb80b6e759dda7ccf11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "088ab884d7ba337b948b21a82f4dcf2a3ed623e59cc800090fe462e53d60666f"

  strings:
    $s1 = "function _QSt3(s) {var _JUi1 = new Date();_JUi1.setUTCFullYear(\"2003\");if (_JUi1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _QSt3(s) {var _JUi1 = new Date();_JUi1.setUTCFullYear(\"2003\");if (_JUi1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Es2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}