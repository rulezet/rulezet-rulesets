rule sig_20161205_edb1a50af1de57187e96d182ad661011 {
  meta:
    description = "datamaliciousorder - file 20161205_edb1a50af1de57187e96d182ad661011.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a80dd4c5e05fe2dfdd681d140621bd937dda7c0b6021dc678bc12e7e3857ef95"

  strings:
    $s1 = "function _El1(s) {var _PIz8 = new Date();_PIz8.setUTCFullYear(\"2003\");if (_PIz8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _El1(s) {var _PIz8 = new Date();_PIz8.setUTCFullYear(\"2003\");if (_PIz8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Rq8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}