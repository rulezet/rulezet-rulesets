rule sig_20161206_56f9d60147729cdba2f9a7738c80328e {
  meta:
    description = "datamaliciousorder - file 20161206_56f9d60147729cdba2f9a7738c80328e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd02f16329084845d6c33f6152db53c67015881e3e702fd7eede6d7155c6c778"

  strings:
    $s1 = "function _Fw7(s) {var _RFv9 = new Date();_RFv9.setUTCFullYear(\"2003\");if (_RFv9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Fw7(s) {var _RFv9 = new Date();_RFv9.setUTCFullYear(\"2003\");if (_RFv9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _FJi5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}