rule sig_20161206_c25026b39738af3a7f06b21d0d3de4ad {
  meta:
    description = "datamaliciousorder - file 20161206_c25026b39738af3a7f06b21d0d3de4ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08f312cc74fdfc947cdb74a3175833ccf66fa8b1f88f25577d4264d2ec3f2c92"

  strings:
    $s1 = "function _WKy4(s) {var _WXe3 = new Date();_WXe3.setUTCFullYear(\"2003\");if (_WXe3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _WKy4(s) {var _WXe3 = new Date();_WXe3.setUTCFullYear(\"2003\");if (_WXe3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Te5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}