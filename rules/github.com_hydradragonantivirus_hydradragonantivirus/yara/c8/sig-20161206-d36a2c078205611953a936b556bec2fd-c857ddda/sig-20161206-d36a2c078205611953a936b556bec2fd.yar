rule sig_20161206_d36a2c078205611953a936b556bec2fd {
  meta:
    description = "datamaliciousorder - file 20161206_d36a2c078205611953a936b556bec2fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2195dfb9581d93ed5159f4a39041848f464b81c4435ed9aefb220c2ec5ccd31"

  strings:
    $s1 = "function _PVn3(s) {var _CQp0 = new Date();_CQp0.setUTCFullYear(\"2003\");if (_CQp0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _PVn3(s) {var _CQp0 = new Date();_CQp0.setUTCFullYear(\"2003\");if (_CQp0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _YDt6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}