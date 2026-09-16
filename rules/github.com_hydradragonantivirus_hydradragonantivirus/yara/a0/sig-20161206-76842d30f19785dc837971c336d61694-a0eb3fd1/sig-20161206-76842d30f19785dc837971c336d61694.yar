rule sig_20161206_76842d30f19785dc837971c336d61694 {
  meta:
    description = "datamaliciousorder - file 20161206_76842d30f19785dc837971c336d61694.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15eb4cd2b8a93a995eddbfacf4c9ce50c34710ffb3a2ea2be4d9cb45aa6af38f"

  strings:
    $s1 = "function _CZl4(s) {var _WBi8 = new Date();_WBi8.setUTCFullYear(\"2003\");if (_WBi8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _CZl4(s) {var _WBi8 = new Date();_WBi8.setUTCFullYear(\"2003\");if (_WBi8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Tw8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}