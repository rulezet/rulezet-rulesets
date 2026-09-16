rule sig_20161206_1a5d9fd34dd952938adf0781efe5a7e5 {
  meta:
    description = "datamaliciousorder - file 20161206_1a5d9fd34dd952938adf0781efe5a7e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ada846fc84b40ed7e48133ba666812ceedadb633841f87950499938986d2f3d8"

  strings:
    $s1 = "function _JNy1(s) {var _FZf6 = new Date();_FZf6.setUTCFullYear(\"2003\");if (_FZf6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _JNy1(s) {var _FZf6 = new Date();_FZf6.setUTCFullYear(\"2003\");if (_FZf6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Sa3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}