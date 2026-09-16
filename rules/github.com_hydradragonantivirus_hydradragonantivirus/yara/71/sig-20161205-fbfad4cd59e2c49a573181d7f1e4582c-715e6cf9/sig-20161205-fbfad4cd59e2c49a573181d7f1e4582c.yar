rule sig_20161205_fbfad4cd59e2c49a573181d7f1e4582c {
  meta:
    description = "datamaliciousorder - file 20161205_fbfad4cd59e2c49a573181d7f1e4582c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0cc9c2b2fdabcaba55c3292a9b98f4ac53b6178119559017bbef08c04c256f7"

  strings:
    $s1 = "function _FIa9(s) {var _Ht1 = new Date();_Ht1.setUTCFullYear(\"2003\");if (_Ht1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _FIa9(s) {var _Ht1 = new Date();_Ht1.setUTCFullYear(\"2003\");if (_Ht1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _ICl1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}