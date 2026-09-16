rule sig_20161206_62d98282e16b73ee7040cdfa70a4386f {
  meta:
    description = "datamaliciousorder - file 20161206_62d98282e16b73ee7040cdfa70a4386f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "167935529c1db5dcbaea91b09548ec3cfcf34c6e4750dfd070e0e32268a49284"

  strings:
    $s1 = "function _BJu3(s) {var _SDf1 = new Date();_SDf1.setUTCFullYear(\"2003\");if (_SDf1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _BJu3(s) {var _SDf1 = new Date();_SDf1.setUTCFullYear(\"2003\");if (_SDf1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _LRa7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}