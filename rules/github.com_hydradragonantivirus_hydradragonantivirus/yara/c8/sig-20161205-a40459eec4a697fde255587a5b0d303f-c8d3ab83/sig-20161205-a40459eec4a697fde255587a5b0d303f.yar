rule sig_20161205_a40459eec4a697fde255587a5b0d303f {
  meta:
    description = "datamaliciousorder - file 20161205_a40459eec4a697fde255587a5b0d303f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "873b4f1753dfae4f48f816e853c3200bdbbd944e6c411c97985a3c93a795278b"

  strings:
    $s1 = "function _Sj3(s) {var _WHe3 = new Date();_WHe3.setUTCFullYear(\"2003\");if (_WHe3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Sj3(s) {var _WHe3 = new Date();_WHe3.setUTCFullYear(\"2003\");if (_WHe3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _NXm2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}