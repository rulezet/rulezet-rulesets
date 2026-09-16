rule sig_20161206_805318cc4ecff6f04eff2bb50fcd5621 {
  meta:
    description = "datamaliciousorder - file 20161206_805318cc4ecff6f04eff2bb50fcd5621.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d634b875d218dfb8281b08bf75b0b13f75e33b9e45619c2aa7a56b6f5891973"

  strings:
    $s1 = "function _Na5(s) {var _Eb5 = new Date();_Eb5.setUTCFullYear(\"2003\");if (_Eb5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Na5(s) {var _Eb5 = new Date();_Eb5.setUTCFullYear(\"2003\");if (_Eb5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Nx9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}