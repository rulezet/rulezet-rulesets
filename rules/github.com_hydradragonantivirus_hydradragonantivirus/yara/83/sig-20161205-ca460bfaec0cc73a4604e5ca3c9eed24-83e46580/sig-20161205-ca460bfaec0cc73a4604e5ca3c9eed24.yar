rule sig_20161205_ca460bfaec0cc73a4604e5ca3c9eed24 {
  meta:
    description = "datamaliciousorder - file 20161205_ca460bfaec0cc73a4604e5ca3c9eed24.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0de4c13dc24b8915555444e279613fe68328e33cf53ffb9f87eaeec9abbc5312"

  strings:
    $s1 = "function _GUk9(s) {var _Iq6 = new Date();_Iq6.setUTCFullYear(\"2003\");if (_Iq6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _GUk9(s) {var _Iq6 = new Date();_Iq6.setUTCFullYear(\"2003\");if (_Iq6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _WDf7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}