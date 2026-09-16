rule sig_20161205_0b3b538ac4764269b8e4583db7be837f {
  meta:
    description = "datamaliciousorder - file 20161205_0b3b538ac4764269b8e4583db7be837f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c05fd49cd621254739e19d0da3477a4b3e5fe8b265f270e3d7a5a1ffda403a90"

  strings:
    $s1 = "function _QNy3(s) {var _PPr5 = new Date();_PPr5.setUTCFullYear(\"2003\");if (_PPr5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _QNy3(s) {var _PPr5 = new Date();_PPr5.setUTCFullYear(\"2003\");if (_PPr5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Pd7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}