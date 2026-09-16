rule sig_20161205_d2ae6f40d26a5a39ba8524cf371f4e67 {
  meta:
    description = "datamaliciousorder - file 20161205_d2ae6f40d26a5a39ba8524cf371f4e67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb8379f10265552b06259de18de307d9159639d40ff1fe781e69f142a18119f5"

  strings:
    $s1 = "function _UJq7(s) {var _Mw8 = new Date();_Mw8.setUTCFullYear(\"2003\");if (_Mw8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _UJq7(s) {var _Mw8 = new Date();_Mw8.setUTCFullYear(\"2003\");if (_Mw8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _BJk6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}