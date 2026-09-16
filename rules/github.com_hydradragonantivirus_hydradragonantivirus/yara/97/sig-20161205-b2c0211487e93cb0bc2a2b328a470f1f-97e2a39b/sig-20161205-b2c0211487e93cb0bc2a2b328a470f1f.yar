rule sig_20161205_b2c0211487e93cb0bc2a2b328a470f1f {
  meta:
    description = "datamaliciousorder - file 20161205_b2c0211487e93cb0bc2a2b328a470f1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4a93af3f992ffef02a358d5d7ae40e69b41859997b0e517d922dc7ad145d931"

  strings:
    $s1 = "function _XNc7(s) {var _YGr8 = new Date();_YGr8.setUTCFullYear(\"2003\");if (_YGr8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _XNc7(s) {var _YGr8 = new Date();_YGr8.setUTCFullYear(\"2003\");if (_YGr8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _UMt0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}