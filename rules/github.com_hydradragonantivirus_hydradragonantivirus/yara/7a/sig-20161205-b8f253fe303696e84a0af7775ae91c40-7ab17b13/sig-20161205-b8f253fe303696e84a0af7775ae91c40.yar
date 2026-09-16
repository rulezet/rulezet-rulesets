rule sig_20161205_b8f253fe303696e84a0af7775ae91c40 {
  meta:
    description = "datamaliciousorder - file 20161205_b8f253fe303696e84a0af7775ae91c40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6810fe24d472a24fb9ebfb0a07371e73facb9629effc7ee3d091b14861cf45b"

  strings:
    $s1 = "function _Qv4(s) {var _Va6 = new Date();_Va6.setUTCFullYear(\"2003\");if (_Va6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Qv4(s) {var _Va6 = new Date();_Va6.setUTCFullYear(\"2003\");if (_Va6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Sr0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}