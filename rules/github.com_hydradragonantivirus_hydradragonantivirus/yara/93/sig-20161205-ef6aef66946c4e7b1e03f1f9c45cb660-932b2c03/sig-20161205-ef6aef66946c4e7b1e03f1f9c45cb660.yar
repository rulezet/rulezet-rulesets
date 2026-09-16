rule sig_20161205_ef6aef66946c4e7b1e03f1f9c45cb660 {
  meta:
    description = "datamaliciousorder - file 20161205_ef6aef66946c4e7b1e03f1f9c45cb660.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e768de4a69f164c537eb8e577a6a6ae1c33b30b60e5963d5ed1f2ba9cf7dcae3"

  strings:
    $s1 = "function _Th1(s) {var _OUx4 = new Date();_OUx4.setUTCFullYear(\"2003\");if (_OUx4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Th1(s) {var _OUx4 = new Date();_OUx4.setUTCFullYear(\"2003\");if (_OUx4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _ONn4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}