rule sig_20161206_ed2f651fd441a0ee20bcf0eceb524086 {
  meta:
    description = "datamaliciousorder - file 20161206_ed2f651fd441a0ee20bcf0eceb524086.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "378416b27dcbbae4e20cb08f04190f43a1ba96b4c6dd28cbbbbc50ae69ca7842"

  strings:
    $s1 = "function _Iw9(s) {var _WOc6 = new Date();_WOc6.setUTCFullYear(\"2003\");if (_WOc6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Iw9(s) {var _WOc6 = new Date();_WOc6.setUTCFullYear(\"2003\");if (_WOc6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Vg2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}