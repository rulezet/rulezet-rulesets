rule sig_20161205_83c3d5fb10ceaccb09a9d51d627e610a {
  meta:
    description = "datamaliciousorder - file 20161205_83c3d5fb10ceaccb09a9d51d627e610a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be00dd63d01552073d2de119ede02a05345e948d59369389863beeea63895395"

  strings:
    $s1 = "function _ONm5(s) {var _QFb4 = new Date();_QFb4.setUTCFullYear(\"2003\");if (_QFb4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ONm5(s) {var _QFb4 = new Date();_QFb4.setUTCFullYear(\"2003\");if (_QFb4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Po4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}