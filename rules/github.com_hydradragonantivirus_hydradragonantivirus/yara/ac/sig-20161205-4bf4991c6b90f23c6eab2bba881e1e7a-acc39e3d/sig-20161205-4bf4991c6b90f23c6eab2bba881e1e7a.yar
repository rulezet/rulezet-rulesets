rule sig_20161205_4bf4991c6b90f23c6eab2bba881e1e7a {
  meta:
    description = "datamaliciousorder - file 20161205_4bf4991c6b90f23c6eab2bba881e1e7a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a442cbfba15a73204e488f82203c8ecf58c5270fe245d827d2a1cda478bf83fd"

  strings:
    $s1 = "function _WYp1(s) {var _Xi0 = new Date();_Xi0.setUTCFullYear(\"2003\");if (_Xi0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _WYp1(s) {var _Xi0 = new Date();_Xi0.setUTCFullYear(\"2003\");if (_Xi0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _YIq7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}