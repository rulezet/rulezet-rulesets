rule sig_20161205_21e91dc082611119eaca79d825bfe034 {
  meta:
    description = "datamaliciousorder - file 20161205_21e91dc082611119eaca79d825bfe034.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb33f75da420506ecae93d619d072699f5a8b511d706966bf842a74c6f8d292a"

  strings:
    $s1 = "function _EKz8(s) {var _BWo1 = new Date();_BWo1.setUTCFullYear(\"2003\");if (_BWo1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _EKz8(s) {var _BWo1 = new Date();_BWo1.setUTCFullYear(\"2003\");if (_BWo1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _BPv8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}