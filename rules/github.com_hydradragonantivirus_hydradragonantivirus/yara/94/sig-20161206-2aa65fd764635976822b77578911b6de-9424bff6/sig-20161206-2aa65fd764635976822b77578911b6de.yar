rule sig_20161206_2aa65fd764635976822b77578911b6de {
  meta:
    description = "datamaliciousorder - file 20161206_2aa65fd764635976822b77578911b6de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdc90769c7a56930362f99c5caa405969f101e16d0cec8c707ba2171efc75d82"

  strings:
    $s1 = "function _Cx7(s) {var _RDl3 = new Date();_RDl3.setUTCFullYear(\"2003\");if (_RDl3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Cx7(s) {var _RDl3 = new Date();_RDl3.setUTCFullYear(\"2003\");if (_RDl3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _XTt0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}