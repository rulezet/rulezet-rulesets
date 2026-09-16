rule sig_20161206_a4e6fa1309c2d9243616c780e68c5403 {
  meta:
    description = "datamaliciousorder - file 20161206_a4e6fa1309c2d9243616c780e68c5403.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb46780a68dc6563c3862c84aeef4454f6e5174c6c71b6d35edf52315a9c8785"

  strings:
    $s1 = "function _KVy8(s) {var _KUl0 = new Date();_KUl0.setUTCFullYear(\"2003\");if (_KUl0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _KVy8(s) {var _KUl0 = new Date();_KUl0.setUTCFullYear(\"2003\");if (_KUl0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Vu1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}