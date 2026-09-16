rule sig_20161205_688cef43f0587f5a868a8ff3073adfc3 {
  meta:
    description = "datamaliciousorder - file 20161205_688cef43f0587f5a868a8ff3073adfc3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d55a3db000a3c02272ea218612b35e1806a4ab692e2daf05f40be01b17a8da3"

  strings:
    $s1 = "function _Vj9(s) {var _ABg0 = new Date();_ABg0.setUTCFullYear(\"2003\");if (_ABg0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Vj9(s) {var _ABg0 = new Date();_ABg0.setUTCFullYear(\"2003\");if (_ABg0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Bn1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}