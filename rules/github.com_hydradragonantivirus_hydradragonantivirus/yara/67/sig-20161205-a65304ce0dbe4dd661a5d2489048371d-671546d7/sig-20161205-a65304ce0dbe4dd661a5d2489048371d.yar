rule sig_20161205_a65304ce0dbe4dd661a5d2489048371d {
  meta:
    description = "datamaliciousorder - file 20161205_a65304ce0dbe4dd661a5d2489048371d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8a01037ee206f7893c8ede3296ef07cb1fe109c73922c747a8b10737d724bc4"

  strings:
    $s1 = "function _Qs8(s) {var _AJo0 = new Date();_AJo0.setUTCFullYear(\"2003\");if (_AJo0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Qs8(s) {var _AJo0 = new Date();_AJo0.setUTCFullYear(\"2003\");if (_AJo0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _UWr1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}