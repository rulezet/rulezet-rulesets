rule sig_20161206_adecd5af6198b28c82ae3241945d23be {
  meta:
    description = "datamaliciousorder - file 20161206_adecd5af6198b28c82ae3241945d23be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3be49a8190c2d7a1cfe84f09e9d1b7d3f3c2740150cffdff4daeb82d3057fa6"

  strings:
    $s1 = "function _LNl5(s) {var _CFm3 = new Date();_CFm3.setUTCFullYear(\"2003\");if (_CFm3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _LNl5(s) {var _CFm3 = new Date();_CFm3.setUTCFullYear(\"2003\");if (_CFm3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Sf9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}