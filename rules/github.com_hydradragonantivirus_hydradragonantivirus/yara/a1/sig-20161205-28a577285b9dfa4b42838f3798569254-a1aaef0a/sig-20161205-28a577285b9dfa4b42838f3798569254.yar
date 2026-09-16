rule sig_20161205_28a577285b9dfa4b42838f3798569254 {
  meta:
    description = "datamaliciousorder - file 20161205_28a577285b9dfa4b42838f3798569254.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1b9cd60384750f7366d10491140364d2abdd5f4964093ab38385aca5dd36e10"

  strings:
    $s1 = "function _YWu5(s) {var _ARk3 = new Date();_ARk3.setUTCFullYear(\"2003\");if (_ARk3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YWu5(s) {var _ARk3 = new Date();_ARk3.setUTCFullYear(\"2003\");if (_ARk3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _MRi9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}