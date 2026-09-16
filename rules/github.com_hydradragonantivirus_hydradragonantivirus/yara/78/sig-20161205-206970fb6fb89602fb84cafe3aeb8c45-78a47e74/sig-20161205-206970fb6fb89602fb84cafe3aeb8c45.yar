rule sig_20161205_206970fb6fb89602fb84cafe3aeb8c45 {
  meta:
    description = "datamaliciousorder - file 20161205_206970fb6fb89602fb84cafe3aeb8c45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "527a89b2891efc72f133568657c1f89b6d659126bb6fe58aecdd3428633f87b6"

  strings:
    $s1 = "function _Yx2(s) {var _EDs6 = new Date();_EDs6.setUTCFullYear(\"2003\");if (_EDs6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Yx2(s) {var _EDs6 = new Date();_EDs6.setUTCFullYear(\"2003\");if (_EDs6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _By1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}