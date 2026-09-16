rule sig_20161205_f5b648ef134a794ab4bc5787210f4f07 {
  meta:
    description = "datamaliciousorder - file 20161205_f5b648ef134a794ab4bc5787210f4f07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e7e49ade41785a603c5f9b4e5ec1e9e362d9f423b24149604c14cb146b6cea2"

  strings:
    $s1 = "function _Tg0(s) {var _JDu1 = new Date();_JDu1.setUTCFullYear(\"2003\");if (_JDu1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Tg0(s) {var _JDu1 = new Date();_JDu1.setUTCFullYear(\"2003\");if (_JDu1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _SVu9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}