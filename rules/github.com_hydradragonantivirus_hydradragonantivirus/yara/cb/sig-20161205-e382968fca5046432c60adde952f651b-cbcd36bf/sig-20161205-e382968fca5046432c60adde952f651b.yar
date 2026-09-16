rule sig_20161205_e382968fca5046432c60adde952f651b {
  meta:
    description = "datamaliciousorder - file 20161205_e382968fca5046432c60adde952f651b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ead9ec39df0b7f5a06e97641f44e26771dfc6efa12e1a947a939ead625b28564"

  strings:
    $s1 = "function _Fj4(s) {var _Lp3 = new Date();_Lp3.setUTCFullYear(\"2003\");if (_Lp3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Fj4(s) {var _Lp3 = new Date();_Lp3.setUTCFullYear(\"2003\");if (_Lp3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _SVq7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}