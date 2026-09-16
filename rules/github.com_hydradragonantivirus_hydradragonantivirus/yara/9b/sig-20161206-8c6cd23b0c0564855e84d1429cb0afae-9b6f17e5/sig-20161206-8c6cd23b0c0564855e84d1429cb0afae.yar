rule sig_20161206_8c6cd23b0c0564855e84d1429cb0afae {
  meta:
    description = "datamaliciousorder - file 20161206_8c6cd23b0c0564855e84d1429cb0afae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "637fcaea4c5f7873c335f0813f4b6c3e41261b5b53f9d01b0e2b0c3064b1075e"

  strings:
    $s1 = "function _Og0(s) {var _JSt6 = new Date();_JSt6.setUTCFullYear(\"2003\");if (_JSt6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Og0(s) {var _JSt6 = new Date();_JSt6.setUTCFullYear(\"2003\");if (_JSt6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Bo6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}