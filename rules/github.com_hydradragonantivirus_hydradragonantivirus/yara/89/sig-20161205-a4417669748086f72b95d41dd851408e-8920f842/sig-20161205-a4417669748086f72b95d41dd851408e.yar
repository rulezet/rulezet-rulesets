rule sig_20161205_a4417669748086f72b95d41dd851408e {
  meta:
    description = "datamaliciousorder - file 20161205_a4417669748086f72b95d41dd851408e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e214b780eca3c113c54c53cca953bdfd48f5a890ba82b660e5fb49d2386491b"

  strings:
    $s1 = "function _Nk1(s) {var _Hi8 = new Date();_Hi8.setUTCFullYear(\"2003\");if (_Hi8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Nk1(s) {var _Hi8 = new Date();_Hi8.setUTCFullYear(\"2003\");if (_Hi8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ad2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}