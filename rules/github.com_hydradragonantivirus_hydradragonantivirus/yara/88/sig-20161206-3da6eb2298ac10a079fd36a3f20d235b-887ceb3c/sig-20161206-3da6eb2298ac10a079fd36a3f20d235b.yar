rule sig_20161206_3da6eb2298ac10a079fd36a3f20d235b {
  meta:
    description = "datamaliciousorder - file 20161206_3da6eb2298ac10a079fd36a3f20d235b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30bbb07b963b3f9c090b9f0f16dd09f1c3a0043b182941916beb8ffe2e4e3a58"

  strings:
    $s1 = "function _Tk4(s) {var _FFa3 = new Date();_FFa3.setUTCFullYear(\"2003\");if (_FFa3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Tk4(s) {var _FFa3 = new Date();_FFa3.setUTCFullYear(\"2003\");if (_FFa3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Xr9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}