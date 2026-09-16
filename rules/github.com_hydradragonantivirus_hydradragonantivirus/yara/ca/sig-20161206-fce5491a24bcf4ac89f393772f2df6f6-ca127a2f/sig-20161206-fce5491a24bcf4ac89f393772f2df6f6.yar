rule sig_20161206_fce5491a24bcf4ac89f393772f2df6f6 {
  meta:
    description = "datamaliciousorder - file 20161206_fce5491a24bcf4ac89f393772f2df6f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "696a04cd293935e41bd24965ee66984c7cb87f3a2843268ef43628358eafcd7c"

  strings:
    $s1 = "function _Xq3(s) {var _UPx2 = new Date();_UPx2.setUTCFullYear(\"2003\");if (_UPx2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Xq3(s) {var _UPx2 = new Date();_UPx2.setUTCFullYear(\"2003\");if (_UPx2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _THg3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}