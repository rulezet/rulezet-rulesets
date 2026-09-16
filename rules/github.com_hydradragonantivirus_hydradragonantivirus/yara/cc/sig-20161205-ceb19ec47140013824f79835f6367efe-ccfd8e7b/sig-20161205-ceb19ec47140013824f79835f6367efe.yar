rule sig_20161205_ceb19ec47140013824f79835f6367efe {
  meta:
    description = "datamaliciousorder - file 20161205_ceb19ec47140013824f79835f6367efe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4df5dfeedf75628e43f180bcc265f47be46fe0b08d0b6ab5f97c9dd7b4277012"

  strings:
    $s1 = "function _Oe5(s) {var _Bh8 = new Date();_Bh8.setUTCFullYear(\"2003\");if (_Bh8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Oe5(s) {var _Bh8 = new Date();_Bh8.setUTCFullYear(\"2003\");if (_Bh8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Fg5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}