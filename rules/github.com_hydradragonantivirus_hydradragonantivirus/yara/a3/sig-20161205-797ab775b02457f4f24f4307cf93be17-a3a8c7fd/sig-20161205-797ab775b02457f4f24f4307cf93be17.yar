rule sig_20161205_797ab775b02457f4f24f4307cf93be17 {
  meta:
    description = "datamaliciousorder - file 20161205_797ab775b02457f4f24f4307cf93be17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f061db8fec84256fe50c9891ba4e420772922ca304501d9981ed9e1816c169c4"

  strings:
    $s1 = "function _Zc8(s) {var _Bk0 = new Date();_Bk0.setUTCFullYear(\"2003\");if (_Bk0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Zc8(s) {var _Bk0 = new Date();_Bk0.setUTCFullYear(\"2003\");if (_Bk0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _MSf7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}