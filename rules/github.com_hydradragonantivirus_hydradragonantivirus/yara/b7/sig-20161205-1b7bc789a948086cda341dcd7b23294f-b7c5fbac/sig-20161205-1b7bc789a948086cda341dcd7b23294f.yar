rule sig_20161205_1b7bc789a948086cda341dcd7b23294f {
  meta:
    description = "datamaliciousorder - file 20161205_1b7bc789a948086cda341dcd7b23294f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "441118f02256cdc5eadfaef97ebf602a7e3b75f08d4480f4c84168f6cad4e793"

  strings:
    $s1 = "function _Ou7(s) {var _PLv9 = new Date();_PLv9.setUTCFullYear(\"2003\");if (_PLv9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ou7(s) {var _PLv9 = new Date();_PLv9.setUTCFullYear(\"2003\");if (_PLv9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Jx2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}