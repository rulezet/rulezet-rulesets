rule sig_20161205_94fe4b523679c1768c23290bc34cdac3 {
  meta:
    description = "datamaliciousorder - file 20161205_94fe4b523679c1768c23290bc34cdac3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f13b107beca495187cc94db665626764a70f20e0652fd73deb1a98f23954e9a0"

  strings:
    $s1 = "function _Yx4(s) {var _ZMm0 = new Date();_ZMm0.setUTCFullYear(\"2003\");if (_ZMm0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Yx4(s) {var _ZMm0 = new Date();_ZMm0.setUTCFullYear(\"2003\");if (_ZMm0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Jh9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}