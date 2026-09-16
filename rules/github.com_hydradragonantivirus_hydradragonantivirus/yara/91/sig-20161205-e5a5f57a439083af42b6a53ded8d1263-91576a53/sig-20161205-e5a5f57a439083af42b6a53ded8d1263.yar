rule sig_20161205_e5a5f57a439083af42b6a53ded8d1263 {
  meta:
    description = "datamaliciousorder - file 20161205_e5a5f57a439083af42b6a53ded8d1263.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df8b3568741fee7a3fe13d8ed6f2870ec541232dca0499a484773553fe9850be"

  strings:
    $s1 = "function _Xv2(s) {var _JVv1 = new Date();_JVv1.setUTCFullYear(\"2003\");if (_JVv1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Xv2(s) {var _JVv1 = new Date();_JVv1.setUTCFullYear(\"2003\");if (_JVv1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Uw2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}