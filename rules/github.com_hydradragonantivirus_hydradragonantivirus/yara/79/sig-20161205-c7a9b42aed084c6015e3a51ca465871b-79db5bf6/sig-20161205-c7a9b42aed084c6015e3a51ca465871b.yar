rule sig_20161205_c7a9b42aed084c6015e3a51ca465871b {
  meta:
    description = "datamaliciousorder - file 20161205_c7a9b42aed084c6015e3a51ca465871b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7f63ace7a572d2aa7d1c59fb429d701d9ef726c193814c195ccae9154a2c555"

  strings:
    $s1 = "function _Bn2(s) {var _Ww3 = new Date();_Ww3.setUTCFullYear(\"2003\");if (_Ww3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Bn2(s) {var _Ww3 = new Date();_Ww3.setUTCFullYear(\"2003\");if (_Ww3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Pv6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}