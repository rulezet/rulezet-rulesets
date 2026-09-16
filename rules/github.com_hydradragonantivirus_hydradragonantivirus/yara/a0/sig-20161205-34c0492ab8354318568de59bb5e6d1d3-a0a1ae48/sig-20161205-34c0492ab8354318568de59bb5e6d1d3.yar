rule sig_20161205_34c0492ab8354318568de59bb5e6d1d3 {
  meta:
    description = "datamaliciousorder - file 20161205_34c0492ab8354318568de59bb5e6d1d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a03d6a6c26d72e4d6bb2b4f6060c005454f8d1470fd696971ca9c6d2710171"

  strings:
    $s1 = "function _Dx9(s) {var _GIc5 = new Date();_GIc5.setUTCFullYear(\"2003\");if (_GIc5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Dx9(s) {var _GIc5 = new Date();_GIc5.setUTCFullYear(\"2003\");if (_GIc5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _JXx2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}