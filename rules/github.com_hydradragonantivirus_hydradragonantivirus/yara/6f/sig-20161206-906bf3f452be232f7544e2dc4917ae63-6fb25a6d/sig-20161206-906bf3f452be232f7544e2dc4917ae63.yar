rule sig_20161206_906bf3f452be232f7544e2dc4917ae63 {
  meta:
    description = "datamaliciousorder - file 20161206_906bf3f452be232f7544e2dc4917ae63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2a14824c9578b1211a6f9d984dd3805e3870d99e6bd4aed332315b9c46b82a2"

  strings:
    $s1 = "function _KCg5(s) {var _DKx6 = new Date();_DKx6.setUTCFullYear(\"2003\");if (_DKx6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _KCg5(s) {var _DKx6 = new Date();_DKx6.setUTCFullYear(\"2003\");if (_DKx6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _TTp9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}