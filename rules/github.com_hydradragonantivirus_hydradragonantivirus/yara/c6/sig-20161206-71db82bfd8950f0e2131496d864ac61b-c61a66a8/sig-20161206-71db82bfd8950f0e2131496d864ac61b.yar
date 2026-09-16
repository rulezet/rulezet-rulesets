rule sig_20161206_71db82bfd8950f0e2131496d864ac61b {
  meta:
    description = "datamaliciousorder - file 20161206_71db82bfd8950f0e2131496d864ac61b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f959f8329db04a68638fef119eed42196ee41899f2cc900d68f62724e86d076e"

  strings:
    $s1 = "function _Fq8(s) {var _VRo7 = new Date();_VRo7.setUTCFullYear(\"2003\");if (_VRo7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Fq8(s) {var _VRo7 = new Date();_VRo7.setUTCFullYear(\"2003\");if (_VRo7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Mi9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}