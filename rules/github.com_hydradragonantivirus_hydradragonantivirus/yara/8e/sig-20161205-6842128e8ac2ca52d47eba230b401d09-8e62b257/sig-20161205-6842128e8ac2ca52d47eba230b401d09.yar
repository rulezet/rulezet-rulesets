rule sig_20161205_6842128e8ac2ca52d47eba230b401d09 {
  meta:
    description = "datamaliciousorder - file 20161205_6842128e8ac2ca52d47eba230b401d09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668e0547a03fbd86dcc0419eafed4a0724cb3c7bc009f35a6f9e1bddbf145fd8"

  strings:
    $s1 = "function _LOh8(s) {var _ACi6 = new Date();_ACi6.setUTCFullYear(\"2003\");if (_ACi6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _LOh8(s) {var _ACi6 = new Date();_ACi6.setUTCFullYear(\"2003\");if (_ACi6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _UTb7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}