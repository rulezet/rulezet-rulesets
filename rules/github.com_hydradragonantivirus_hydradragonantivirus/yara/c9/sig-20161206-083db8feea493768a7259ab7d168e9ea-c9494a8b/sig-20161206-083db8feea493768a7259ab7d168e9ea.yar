rule sig_20161206_083db8feea493768a7259ab7d168e9ea {
  meta:
    description = "datamaliciousorder - file 20161206_083db8feea493768a7259ab7d168e9ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cea064d067e9e99ce43d42d4444b0201a436e7e1e2fda4869284dde58c6b7fb0"

  strings:
    $s1 = "function _Gp3(s) {var _Ne4 = new Date();_Ne4.setUTCFullYear(\"2003\");if (_Ne4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Gp3(s) {var _Ne4 = new Date();_Ne4.setUTCFullYear(\"2003\");if (_Ne4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _SVh6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}