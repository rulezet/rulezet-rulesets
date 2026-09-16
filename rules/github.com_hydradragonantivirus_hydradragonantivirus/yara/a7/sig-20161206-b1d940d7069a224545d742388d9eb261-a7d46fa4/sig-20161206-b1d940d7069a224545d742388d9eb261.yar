rule sig_20161206_b1d940d7069a224545d742388d9eb261 {
  meta:
    description = "datamaliciousorder - file 20161206_b1d940d7069a224545d742388d9eb261.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b971a9f89732750c34ec90db4bb4edf5afbf0c007abcecd7460c8ec176f0c3f"

  strings:
    $s1 = "function _QUi1(s) {var _Nw4 = new Date();_Nw4.setUTCFullYear(\"2003\");if (_Nw4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _QUi1(s) {var _Nw4 = new Date();_Nw4.setUTCFullYear(\"2003\");if (_Nw4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Kg5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}