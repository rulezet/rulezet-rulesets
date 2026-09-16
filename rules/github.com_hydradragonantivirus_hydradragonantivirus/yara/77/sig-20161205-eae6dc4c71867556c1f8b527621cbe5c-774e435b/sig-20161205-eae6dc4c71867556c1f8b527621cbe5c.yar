rule sig_20161205_eae6dc4c71867556c1f8b527621cbe5c {
  meta:
    description = "datamaliciousorder - file 20161205_eae6dc4c71867556c1f8b527621cbe5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fb7b56d1d31111ca0ade115a02eb6b04bfc5f0f737ddaed38360abc5fa24be4"

  strings:
    $s1 = "function _Ex9(s) {var _Zd7 = new Date();_Zd7.setUTCFullYear(\"2003\");if (_Zd7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ex9(s) {var _Zd7 = new Date();_Zd7.setUTCFullYear(\"2003\");if (_Zd7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _RLt6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}