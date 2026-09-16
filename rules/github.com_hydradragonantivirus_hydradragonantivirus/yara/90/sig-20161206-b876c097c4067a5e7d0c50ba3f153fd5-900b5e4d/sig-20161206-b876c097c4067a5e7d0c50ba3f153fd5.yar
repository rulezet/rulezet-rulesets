rule sig_20161206_b876c097c4067a5e7d0c50ba3f153fd5 {
  meta:
    description = "datamaliciousorder - file 20161206_b876c097c4067a5e7d0c50ba3f153fd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75b5f24aa727c61002f65d7920c6dcdd1eaaff4977bea6329e6934dfd46bffd6"

  strings:
    $s1 = "function _Pl3(s) {var _KEq6 = new Date();_KEq6.setUTCFullYear(\"2003\");if (_KEq6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Pl3(s) {var _KEq6 = new Date();_KEq6.setUTCFullYear(\"2003\");if (_KEq6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _JDx9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}