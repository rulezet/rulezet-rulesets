rule sig_20161206_105eb8af45915e34c1f5ed880cb4eee4 {
  meta:
    description = "datamaliciousorder - file 20161206_105eb8af45915e34c1f5ed880cb4eee4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25f99928696884c728b5bed418326ace7617555f0721408187eb1aaf9b6033a4"

  strings:
    $s1 = "function _FKv4(s) {var _Cd6 = new Date();_Cd6.setUTCFullYear(\"2003\");if (_Cd6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _FKv4(s) {var _Cd6 = new Date();_Cd6.setUTCFullYear(\"2003\");if (_Cd6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _El8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}