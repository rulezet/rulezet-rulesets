rule sig_20161205_48f81213f326b9de79b192b20f429bf3 {
  meta:
    description = "datamaliciousorder - file 20161205_48f81213f326b9de79b192b20f429bf3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5fbb56e822931dc913620073b480d5ff04c998ad35b036c8695051ab96042d3"

  strings:
    $s1 = "function _Cm9(s) {var _RAg8 = new Date();_RAg8.setUTCFullYear(\"2003\");if (_RAg8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Cm9(s) {var _RAg8 = new Date();_RAg8.setUTCFullYear(\"2003\");if (_RAg8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Oo6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}