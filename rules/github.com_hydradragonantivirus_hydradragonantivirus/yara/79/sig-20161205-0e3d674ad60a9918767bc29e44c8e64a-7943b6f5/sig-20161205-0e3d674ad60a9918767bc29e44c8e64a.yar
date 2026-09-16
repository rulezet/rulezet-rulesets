rule sig_20161205_0e3d674ad60a9918767bc29e44c8e64a {
  meta:
    description = "datamaliciousorder - file 20161205_0e3d674ad60a9918767bc29e44c8e64a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2a76353bae13abd017977a85c59d864098bee5e341e83e9dc112b3b57cbc5bf"

  strings:
    $s1 = "function _HZy1(s) {var _OSp2 = new Date();_OSp2.setUTCFullYear(\"2003\");if (_OSp2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _HZy1(s) {var _OSp2 = new Date();_OSp2.setUTCFullYear(\"2003\");if (_OSp2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Se6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}