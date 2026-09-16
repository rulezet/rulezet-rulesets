rule sig_20161205_9d6f673736d853949dd39e42a7f600a4 {
  meta:
    description = "datamaliciousorder - file 20161205_9d6f673736d853949dd39e42a7f600a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db44ca719dfb16c2726388a23a021f6349da999bf94bfc59ef59f0fb9499cc50"

  strings:
    $s1 = "function _UWg1(s) {var _TKf8 = new Date();_TKf8.setUTCFullYear(\"2003\");if (_TKf8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _UWg1(s) {var _TKf8 = new Date();_TKf8.setUTCFullYear(\"2003\");if (_TKf8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Aa0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}