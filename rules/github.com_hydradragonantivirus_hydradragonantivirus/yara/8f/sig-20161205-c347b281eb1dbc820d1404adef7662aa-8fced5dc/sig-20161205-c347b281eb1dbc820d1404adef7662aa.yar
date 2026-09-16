rule sig_20161205_c347b281eb1dbc820d1404adef7662aa {
  meta:
    description = "datamaliciousorder - file 20161205_c347b281eb1dbc820d1404adef7662aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "508bee731e009e077d90bb9fbde91abf1fd037413e13301c34fde90da8983687"

  strings:
    $s1 = "function _Eu0(s) {var _BEw5 = new Date();_BEw5.setUTCFullYear(\"2003\");if (_BEw5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Eu0(s) {var _BEw5 = new Date();_BEw5.setUTCFullYear(\"2003\");if (_BEw5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Zq5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}