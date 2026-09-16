rule sig_20161205_8af3c16c78500ed599f803fd65cd810b {
  meta:
    description = "datamaliciousorder - file 20161205_8af3c16c78500ed599f803fd65cd810b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "189af4a1fa9eb0644ba370beb4d08603596ff89e8769a555fb89d9c56fafc7a6"

  strings:
    $s1 = "function _Rq7(s) {var _Rv5 = new Date();_Rv5.setUTCFullYear(\"2003\");if (_Rv5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Rq7(s) {var _Rv5 = new Date();_Rv5.setUTCFullYear(\"2003\");if (_Rv5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Vj4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}