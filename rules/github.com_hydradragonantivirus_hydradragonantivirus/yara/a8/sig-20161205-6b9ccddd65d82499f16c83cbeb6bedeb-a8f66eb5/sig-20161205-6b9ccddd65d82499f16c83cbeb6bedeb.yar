rule sig_20161205_6b9ccddd65d82499f16c83cbeb6bedeb {
  meta:
    description = "datamaliciousorder - file 20161205_6b9ccddd65d82499f16c83cbeb6bedeb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1799fe7a6be3c848473da134fde2f034fa394f6d60671c466efc37eac7cdbaf8"

  strings:
    $s1 = "function _Kc8(s) {var _HHy0 = new Date();_HHy0.setUTCFullYear(\"2003\");if (_HHy0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Kc8(s) {var _HHy0 = new Date();_HHy0.setUTCFullYear(\"2003\");if (_HHy0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _RIi9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}