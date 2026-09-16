rule sig_20161206_f27b1a1349bcd6f4bee3347e7b9d8d41 {
  meta:
    description = "datamaliciousorder - file 20161206_f27b1a1349bcd6f4bee3347e7b9d8d41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91664d197a2234d19029269c1f7626e8a934fcaa90829acac34c61f33e7d3cd4"

  strings:
    $s1 = "function _Vv6(s) {var _QLp3 = new Date();_QLp3.setUTCFullYear(\"2003\");if (_QLp3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Vv6(s) {var _QLp3 = new Date();_QLp3.setUTCFullYear(\"2003\");if (_QLp3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Vo6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}