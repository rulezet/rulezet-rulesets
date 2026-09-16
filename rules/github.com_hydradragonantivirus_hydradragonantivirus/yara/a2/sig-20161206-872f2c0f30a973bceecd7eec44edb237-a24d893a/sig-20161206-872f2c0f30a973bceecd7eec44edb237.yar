rule sig_20161206_872f2c0f30a973bceecd7eec44edb237 {
  meta:
    description = "datamaliciousorder - file 20161206_872f2c0f30a973bceecd7eec44edb237.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8dcd9eb955cf72f0acbcfebd98d6da115c42905c59b70e7a0eab53b74af05e"

  strings:
    $s1 = "function _KCz5(s) {var _XXf4 = new Date();_XXf4.setUTCFullYear(\"2003\");if (_XXf4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _KCz5(s) {var _XXf4 = new Date();_XXf4.setUTCFullYear(\"2003\");if (_XXf4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _XCp9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}