rule sig_20161205_116b1fbed6e41035c06fffbf43a8bd38 {
  meta:
    description = "datamaliciousorder - file 20161205_116b1fbed6e41035c06fffbf43a8bd38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db83e971d6fdfa57cb680c9e36aa7930f8a6e65cbe605f269ea4314446b2bf69"

  strings:
    $s1 = "function _Yi5(s) {var _Hi4 = new Date();_Hi4.setUTCFullYear(\"2003\");if (_Hi4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Yi5(s) {var _Hi4 = new Date();_Hi4.setUTCFullYear(\"2003\");if (_Hi4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _XDs3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}