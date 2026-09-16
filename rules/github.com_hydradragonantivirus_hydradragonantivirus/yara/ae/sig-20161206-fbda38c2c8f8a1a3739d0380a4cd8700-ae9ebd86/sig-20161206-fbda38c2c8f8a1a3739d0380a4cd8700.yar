rule sig_20161206_fbda38c2c8f8a1a3739d0380a4cd8700 {
  meta:
    description = "datamaliciousorder - file 20161206_fbda38c2c8f8a1a3739d0380a4cd8700.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "579d1a2928c37e043affaea38dbb1d659a3ebdf8cd51b2f242261af1114d4aab"

  strings:
    $s1 = "function _Cv3(s) {var _Fw2 = new Date();_Fw2.setUTCFullYear(\"2003\");if (_Fw2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Cv3(s) {var _Fw2 = new Date();_Fw2.setUTCFullYear(\"2003\");if (_Fw2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _NQx2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}