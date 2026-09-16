rule sig_20161205_403daebe142f8bdf56f84621172a9ccc {
  meta:
    description = "datamaliciousorder - file 20161205_403daebe142f8bdf56f84621172a9ccc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea557e2520afa9c86aca9dee555c08a13127e4acc9a95f05aac5e74f6aaff62d"

  strings:
    $s1 = "function _Hd6(s) {var _Zm1 = new Date();_Zm1.setUTCFullYear(\"2003\");if (_Zm1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Hd6(s) {var _Zm1 = new Date();_Zm1.setUTCFullYear(\"2003\");if (_Zm1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ip1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}