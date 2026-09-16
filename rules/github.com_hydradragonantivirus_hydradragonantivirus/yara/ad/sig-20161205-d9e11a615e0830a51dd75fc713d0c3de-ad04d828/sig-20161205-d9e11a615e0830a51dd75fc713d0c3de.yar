rule sig_20161205_d9e11a615e0830a51dd75fc713d0c3de {
  meta:
    description = "datamaliciousorder - file 20161205_d9e11a615e0830a51dd75fc713d0c3de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d29966b5243fe3c004a794fe7ec7785008d9f70f029fd6010624e734c92937a2"

  strings:
    $s1 = "function _ZRi4(s) {var _Vp8 = new Date();_Vp8.setUTCFullYear(\"2003\");if (_Vp8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ZRi4(s) {var _Vp8 = new Date();_Vp8.setUTCFullYear(\"2003\");if (_Vp8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ts0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}