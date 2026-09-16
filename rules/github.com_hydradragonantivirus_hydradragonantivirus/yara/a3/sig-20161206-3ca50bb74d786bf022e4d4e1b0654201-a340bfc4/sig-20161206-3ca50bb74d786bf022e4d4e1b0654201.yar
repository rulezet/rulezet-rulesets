rule sig_20161206_3ca50bb74d786bf022e4d4e1b0654201 {
  meta:
    description = "datamaliciousorder - file 20161206_3ca50bb74d786bf022e4d4e1b0654201.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fe4edbfbbae4b8ea47c8de4303acee8ffad34e7782e7f490a45dcfdb030fffb"

  strings:
    $s1 = "function _He8(s) {var _ENy7 = new Date();_ENy7.setUTCFullYear(\"2003\");if (_ENy7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _He8(s) {var _ENy7 = new Date();_ENy7.setUTCFullYear(\"2003\");if (_ENy7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _MAw7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}