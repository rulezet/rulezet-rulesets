rule sig_20161206_a165823e349589abfcdc6e94110bb66f {
  meta:
    description = "datamaliciousorder - file 20161206_a165823e349589abfcdc6e94110bb66f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d35df2b036474c389c865b7529d22dc112fc9cec70e8360eff4f537e0c0a281"

  strings:
    $s1 = "function _Ic8(s) {var _Bi8 = new Date();_Bi8.setUTCFullYear(\"2003\");if (_Bi8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ic8(s) {var _Bi8 = new Date();_Bi8.setUTCFullYear(\"2003\");if (_Bi8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Dz0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}