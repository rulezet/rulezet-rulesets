rule sig_20161206_e35bb59f5e26be98befb195cd96cce95 {
  meta:
    description = "datamaliciousorder - file 20161206_e35bb59f5e26be98befb195cd96cce95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "676ba1eb6e3cd18e32a7c4e2bd1e651b82b524cb547a4420a46c067f62595255"

  strings:
    $s1 = "function _ZBy7(s) {var _Vh4 = new Date();_Vh4.setUTCFullYear(\"2003\");if (_Vh4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ZBy7(s) {var _Vh4 = new Date();_Vh4.setUTCFullYear(\"2003\");if (_Vh4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Kq5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}