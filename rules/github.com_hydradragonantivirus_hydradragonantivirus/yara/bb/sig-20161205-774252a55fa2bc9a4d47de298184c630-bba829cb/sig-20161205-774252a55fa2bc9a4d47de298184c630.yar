rule sig_20161205_774252a55fa2bc9a4d47de298184c630 {
  meta:
    description = "datamaliciousorder - file 20161205_774252a55fa2bc9a4d47de298184c630.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00d581dc0395d74e123ae48c9251b980a0063b00f99c6fd39e4907a48ffed954"

  strings:
    $s1 = "function _Lx5(s) {var _RVr8 = new Date();_RVr8.setUTCFullYear(\"2003\");if (_RVr8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Lx5(s) {var _RVr8 = new Date();_RVr8.setUTCFullYear(\"2003\");if (_RVr8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Jl5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}