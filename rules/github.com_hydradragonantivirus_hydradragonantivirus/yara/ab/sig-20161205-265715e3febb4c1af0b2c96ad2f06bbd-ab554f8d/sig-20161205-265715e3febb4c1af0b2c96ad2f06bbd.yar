rule sig_20161205_265715e3febb4c1af0b2c96ad2f06bbd {
  meta:
    description = "datamaliciousorder - file 20161205_265715e3febb4c1af0b2c96ad2f06bbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae60e460b8b12b4925520fe078050af701ca0d2622affb5028c928036aca3da3"

  strings:
    $s1 = "function _Zo2(s) {var _Is8 = new Date();_Is8.setUTCFullYear(\"2003\");if (_Is8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Zo2(s) {var _Is8 = new Date();_Is8.setUTCFullYear(\"2003\");if (_Is8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _VZp1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}