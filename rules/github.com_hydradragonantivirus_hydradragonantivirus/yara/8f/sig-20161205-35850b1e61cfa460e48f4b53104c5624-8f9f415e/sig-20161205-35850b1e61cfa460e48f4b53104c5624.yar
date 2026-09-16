rule sig_20161205_35850b1e61cfa460e48f4b53104c5624 {
  meta:
    description = "datamaliciousorder - file 20161205_35850b1e61cfa460e48f4b53104c5624.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1052f01d074a788c4370400986823fcdaf15eb1df61be77b8a4745860e42e148"

  strings:
    $s1 = "function _BDy8(s) {var _Yt5 = new Date();_Yt5.setUTCFullYear(\"2003\");if (_Yt5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _BDy8(s) {var _Yt5 = new Date();_Yt5.setUTCFullYear(\"2003\");if (_Yt5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _ICe4(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}