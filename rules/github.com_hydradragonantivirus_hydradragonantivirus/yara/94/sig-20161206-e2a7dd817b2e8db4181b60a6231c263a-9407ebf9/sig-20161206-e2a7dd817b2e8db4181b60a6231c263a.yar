rule sig_20161206_e2a7dd817b2e8db4181b60a6231c263a {
  meta:
    description = "datamaliciousorder - file 20161206_e2a7dd817b2e8db4181b60a6231c263a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2ddbe3cf39e2ffe8d9feec57891248fa71d8a7cb656b68a6b18e87c9a44ad13"

  strings:
    $s1 = "function _Xq1(s) {var _GTh8 = new Date();_GTh8.setUTCFullYear(\"2003\");if (_GTh8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Xq1(s) {var _GTh8 = new Date();_GTh8.setUTCFullYear(\"2003\");if (_GTh8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _MQt0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}