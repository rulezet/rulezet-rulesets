rule sig_20161205_dd488e222a345fdd8ef153114b3094cb {
  meta:
    description = "datamaliciousorder - file 20161205_dd488e222a345fdd8ef153114b3094cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a79ed1c18380f37592f4d1740f279f821d4d3fd8c086f85fe884362fb2cb584"

  strings:
    $s1 = "function _TUm3(s) {var _SGj0 = new Date();_SGj0.setUTCFullYear(\"2003\");if (_SGj0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _TUm3(s) {var _SGj0 = new Date();_SGj0.setUTCFullYear(\"2003\");if (_SGj0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _TRd8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}