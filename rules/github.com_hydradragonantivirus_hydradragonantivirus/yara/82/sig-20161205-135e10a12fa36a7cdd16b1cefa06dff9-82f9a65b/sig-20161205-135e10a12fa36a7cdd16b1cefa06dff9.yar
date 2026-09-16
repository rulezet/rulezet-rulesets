rule sig_20161205_135e10a12fa36a7cdd16b1cefa06dff9 {
  meta:
    description = "datamaliciousorder - file 20161205_135e10a12fa36a7cdd16b1cefa06dff9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32b286d6a5e21707d3dc7511a105509232d6525e35980bfb97855de3566ca93f"

  strings:
    $s1 = "function _Mb1(s) {var _HWq2 = new Date();_HWq2.setUTCFullYear(\"2003\");if (_HWq2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Mb1(s) {var _HWq2 = new Date();_HWq2.setUTCFullYear(\"2003\");if (_HWq2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _TYu1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}