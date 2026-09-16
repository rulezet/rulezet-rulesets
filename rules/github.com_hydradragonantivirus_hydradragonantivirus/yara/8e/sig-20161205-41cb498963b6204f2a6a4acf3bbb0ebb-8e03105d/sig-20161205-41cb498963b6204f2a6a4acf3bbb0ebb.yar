rule sig_20161205_41cb498963b6204f2a6a4acf3bbb0ebb {
  meta:
    description = "datamaliciousorder - file 20161205_41cb498963b6204f2a6a4acf3bbb0ebb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "235e1733839cac6420a2cd1c3bd2fdb1eeb718ebde17d014aa0732f00706241c"

  strings:
    $s1 = "function _WQp3(s) {var _ACp6 = new Date();_ACp6.setUTCFullYear(\"2003\");if (_ACp6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _WQp3(s) {var _ACp6 = new Date();_ACp6.setUTCFullYear(\"2003\");if (_ACp6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _JMu7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}