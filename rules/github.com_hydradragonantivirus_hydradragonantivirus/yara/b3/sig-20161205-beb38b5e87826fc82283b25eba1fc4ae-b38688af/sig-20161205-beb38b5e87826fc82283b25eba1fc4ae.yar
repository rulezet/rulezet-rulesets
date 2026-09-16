rule sig_20161205_beb38b5e87826fc82283b25eba1fc4ae {
  meta:
    description = "datamaliciousorder - file 20161205_beb38b5e87826fc82283b25eba1fc4ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a47759d1dd146df20aa6aee0cc33a671b1f8fc89c4e44656abc501454eacc84c"

  strings:
    $s1 = "function _UDy9(s) {var _Aa3 = new Date();_Aa3.setUTCFullYear(\"2003\");if (_Aa3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _UDy9(s) {var _Aa3 = new Date();_Aa3.setUTCFullYear(\"2003\");if (_Aa3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _TIb9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}