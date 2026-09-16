rule sig_20161205_f34a73b45181aa2ff57888a074bdae4c {
  meta:
    description = "datamaliciousorder - file 20161205_f34a73b45181aa2ff57888a074bdae4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99194ecbd25b099e2c12a57fd5f90094d1b1e514d8f997b052d2c3cbd1db5695"

  strings:
    $s1 = "function _IPl3(s) {var _Cu7 = new Date();_Cu7.setUTCFullYear(\"2003\");if (_Cu7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _IPl3(s) {var _Cu7 = new Date();_Cu7.setUTCFullYear(\"2003\");if (_Cu7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _LOx5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}