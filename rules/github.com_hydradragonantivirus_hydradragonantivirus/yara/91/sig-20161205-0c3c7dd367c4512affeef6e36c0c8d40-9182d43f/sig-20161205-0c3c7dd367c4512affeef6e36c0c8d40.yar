rule sig_20161205_0c3c7dd367c4512affeef6e36c0c8d40 {
  meta:
    description = "datamaliciousorder - file 20161205_0c3c7dd367c4512affeef6e36c0c8d40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2c319d8e96717b08fbebdd6f3d87713813c31bfdb515bb7d657d750bd5dcef3"

  strings:
    $s1 = "function _Wd8(s) {var _PHg0 = new Date();_PHg0.setUTCFullYear(\"2003\");if (_PHg0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Wd8(s) {var _PHg0 = new Date();_PHg0.setUTCFullYear(\"2003\");if (_PHg0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _AKt7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}