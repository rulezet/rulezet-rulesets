rule sig_20161205_bf88b213b570d9a63afee6f91c5de592 {
  meta:
    description = "datamaliciousorder - file 20161205_bf88b213b570d9a63afee6f91c5de592.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e25d3a5d194851d9494f06ed0f43f18a91a5a95a317eebdab1185a1cbb98ee67"

  strings:
    $s1 = "function _Xo5(s) {var _Pc5 = new Date();_Pc5.setUTCFullYear(\"2003\");if (_Pc5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Xo5(s) {var _Pc5 = new Date();_Pc5.setUTCFullYear(\"2003\");if (_Pc5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _UHl8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}