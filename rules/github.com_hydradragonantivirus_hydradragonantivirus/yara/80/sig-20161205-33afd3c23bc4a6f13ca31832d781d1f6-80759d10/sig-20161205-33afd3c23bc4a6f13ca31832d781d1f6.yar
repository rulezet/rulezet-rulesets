rule sig_20161205_33afd3c23bc4a6f13ca31832d781d1f6 {
  meta:
    description = "datamaliciousorder - file 20161205_33afd3c23bc4a6f13ca31832d781d1f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92fb73b671f45e813cdd710d0dae0d50b83ebc83d84ab48c9a0f79054b5c6582"

  strings:
    $s1 = "function _Hu1(s) {var _LJt9 = new Date();_LJt9.setUTCFullYear(\"2003\");if (_LJt9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Hu1(s) {var _LJt9 = new Date();_LJt9.setUTCFullYear(\"2003\");if (_LJt9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _PIi3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}