rule sig_20161205_7bf6807c7282952d048ea2b008331866 {
  meta:
    description = "datamaliciousorder - file 20161205_7bf6807c7282952d048ea2b008331866.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fdf863dace72aa213ef8b5a1545878e7b5eb398b416d14f1b734eddb80fc76a"

  strings:
    $s1 = "function _Rq8(s) {var _VWv8 = new Date();_VWv8.setUTCFullYear(\"2003\");if (_VWv8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Rq8(s) {var _VWv8 = new Date();_VWv8.setUTCFullYear(\"2003\");if (_VWv8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Bp9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}