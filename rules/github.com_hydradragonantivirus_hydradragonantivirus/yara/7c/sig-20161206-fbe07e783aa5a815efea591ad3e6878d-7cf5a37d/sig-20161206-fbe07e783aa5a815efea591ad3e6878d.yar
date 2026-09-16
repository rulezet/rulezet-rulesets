rule sig_20161206_fbe07e783aa5a815efea591ad3e6878d {
  meta:
    description = "datamaliciousorder - file 20161206_fbe07e783aa5a815efea591ad3e6878d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "125f2e92fe16404b3553b05bf22781b08f3a2011075e599a3c93e1188153e3b5"

  strings:
    $s1 = "function _Xb3(s) {var _RXd9 = new Date();_RXd9.setUTCFullYear(\"2003\");if (_RXd9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Xb3(s) {var _RXd9 = new Date();_RXd9.setUTCFullYear(\"2003\");if (_RXd9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _QMc0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}