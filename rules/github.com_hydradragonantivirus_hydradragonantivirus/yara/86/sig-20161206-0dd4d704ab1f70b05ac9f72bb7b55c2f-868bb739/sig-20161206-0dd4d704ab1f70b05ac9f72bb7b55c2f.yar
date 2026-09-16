rule sig_20161206_0dd4d704ab1f70b05ac9f72bb7b55c2f {
  meta:
    description = "datamaliciousorder - file 20161206_0dd4d704ab1f70b05ac9f72bb7b55c2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "236b7fd63516021bcdce3993951decda88b85340319fcc58236f31f563c20109"

  strings:
    $s1 = "function _Op5(s) {var _MLf0 = new Date();_MLf0.setUTCFullYear(\"2003\");if (_MLf0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Op5(s) {var _MLf0 = new Date();_MLf0.setUTCFullYear(\"2003\");if (_MLf0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _DUp0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}