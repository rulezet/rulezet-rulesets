rule sig_20161206_c9329bb37c9647453d16724af7d56a4a {
  meta:
    description = "datamaliciousorder - file 20161206_c9329bb37c9647453d16724af7d56a4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eaad294288c2ab1e24f3d86e7dd0558b6c9dfdf171f3f6cfe7d3978486662e76"

  strings:
    $s1 = "function _Za6(s) {var _Aa5 = new Date();_Aa5.setUTCFullYear(\"2003\");if (_Aa5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Za6(s) {var _Aa5 = new Date();_Aa5.setUTCFullYear(\"2003\");if (_Aa5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Tq7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}