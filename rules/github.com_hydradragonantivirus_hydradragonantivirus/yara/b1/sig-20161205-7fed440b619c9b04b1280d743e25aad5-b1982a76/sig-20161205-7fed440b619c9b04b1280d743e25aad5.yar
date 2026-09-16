rule sig_20161205_7fed440b619c9b04b1280d743e25aad5 {
  meta:
    description = "datamaliciousorder - file 20161205_7fed440b619c9b04b1280d743e25aad5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "583c132acdabfea0abd400ef01d77f1d46317be8ebaefc8fca42dceec4a48a9d"

  strings:
    $s1 = "function _Uu0(s) {var _Pq6 = new Date();_Pq6.setUTCFullYear(\"2003\");if (_Pq6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Uu0(s) {var _Pq6 = new Date();_Pq6.setUTCFullYear(\"2003\");if (_Pq6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Pn3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}