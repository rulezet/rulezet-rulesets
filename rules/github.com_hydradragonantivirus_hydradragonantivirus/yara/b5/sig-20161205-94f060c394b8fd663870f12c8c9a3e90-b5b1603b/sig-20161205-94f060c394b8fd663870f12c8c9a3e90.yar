rule sig_20161205_94f060c394b8fd663870f12c8c9a3e90 {
  meta:
    description = "datamaliciousorder - file 20161205_94f060c394b8fd663870f12c8c9a3e90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bd625c8126115170035588a31434207e5b0a0de90e0ea37d0d7e6890cc947b6"

  strings:
    $s1 = "function _At9(s) {var _OUf4 = new Date();_OUf4.setUTCFullYear(\"2003\");if (_OUf4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _At9(s) {var _OUf4 = new Date();_OUf4.setUTCFullYear(\"2003\");if (_OUf4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ms6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}