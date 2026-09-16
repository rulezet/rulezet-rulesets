rule sig_20161205_216db6d550c11784aa3399b82db85dc6 {
  meta:
    description = "datamaliciousorder - file 20161205_216db6d550c11784aa3399b82db85dc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3dabcd8ed610de035ce44641e424dd90046444e5b1a1e3422a5ad951877e8f5"

  strings:
    $s1 = "function _MEl9(s) {var _MPw6 = new Date();_MPw6.setUTCFullYear(\"2003\");if (_MPw6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _MEl9(s) {var _MPw6 = new Date();_MPw6.setUTCFullYear(\"2003\");if (_MPw6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _YGq3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}