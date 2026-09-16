rule sig_20161206_92827adbc178991d8bf32edd12fa3987 {
  meta:
    description = "datamaliciousorder - file 20161206_92827adbc178991d8bf32edd12fa3987.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "512cfc987e8b1b0a5254ec2d77c9ec27b25a38354e8f0d67514df4b7c3788800"

  strings:
    $s1 = "function _PZd5(s) {var _WBv2 = new Date();_WBv2.setUTCFullYear(\"2003\");if (_WBv2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _PZd5(s) {var _WBv2 = new Date();_WBv2.setUTCFullYear(\"2003\");if (_WBv2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _VKm3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}