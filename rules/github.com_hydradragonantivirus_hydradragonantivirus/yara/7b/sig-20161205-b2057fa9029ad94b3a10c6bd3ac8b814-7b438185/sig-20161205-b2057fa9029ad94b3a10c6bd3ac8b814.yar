rule sig_20161205_b2057fa9029ad94b3a10c6bd3ac8b814 {
  meta:
    description = "datamaliciousorder - file 20161205_b2057fa9029ad94b3a10c6bd3ac8b814.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fa5239194f72d2fa8c775b58448204e5fd8faab2ade257bbb8b44ed9a3f52ca"

  strings:
    $s1 = "function _YHt7(s) {var _UFh3 = new Date();_UFh3.setUTCFullYear(\"2003\");if (_UFh3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YHt7(s) {var _UFh3 = new Date();_UFh3.setUTCFullYear(\"2003\");if (_UFh3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ha6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}