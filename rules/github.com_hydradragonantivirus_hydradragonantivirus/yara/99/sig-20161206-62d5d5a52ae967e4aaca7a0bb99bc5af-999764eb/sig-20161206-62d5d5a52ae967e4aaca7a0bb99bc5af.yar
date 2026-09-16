rule sig_20161206_62d5d5a52ae967e4aaca7a0bb99bc5af {
  meta:
    description = "datamaliciousorder - file 20161206_62d5d5a52ae967e4aaca7a0bb99bc5af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ab59be2d04b46447fe1dc6531ee2f3113ea0c7cf48e4616d146501154b07c1b"

  strings:
    $s1 = "function _FLo9(s) {var _Fe1 = new Date();_Fe1.setUTCFullYear(\"2003\");if (_Fe1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _FLo9(s) {var _Fe1 = new Date();_Fe1.setUTCFullYear(\"2003\");if (_Fe1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ge5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}