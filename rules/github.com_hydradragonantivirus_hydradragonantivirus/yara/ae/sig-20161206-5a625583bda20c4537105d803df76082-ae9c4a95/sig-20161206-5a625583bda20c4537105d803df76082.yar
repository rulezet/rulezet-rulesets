rule sig_20161206_5a625583bda20c4537105d803df76082 {
  meta:
    description = "datamaliciousorder - file 20161206_5a625583bda20c4537105d803df76082.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6398f5896850148e7096934c65997d6e22210597a99f23320eaf889cde175a7"

  strings:
    $s1 = "function _Qm3(s) {var _BJi2 = new Date();_BJi2.setUTCFullYear(\"2003\");if (_BJi2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Qm3(s) {var _BJi2 = new Date();_BJi2.setUTCFullYear(\"2003\");if (_BJi2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _CQl5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}