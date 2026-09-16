rule sig_20161206_89f3a575825ef5251c007e86dd6c021a {
  meta:
    description = "datamaliciousorder - file 20161206_89f3a575825ef5251c007e86dd6c021a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ccdacecf814baff51282656e11361d931c5a0ecc8c908146925b08ebf1070afa"

  strings:
    $s1 = "function _Wd4(s) {var _WJh8 = new Date();_WJh8.setUTCFullYear(\"2003\");if (_WJh8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Wd4(s) {var _WJh8 = new Date();_WJh8.setUTCFullYear(\"2003\");if (_WJh8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Wf3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}