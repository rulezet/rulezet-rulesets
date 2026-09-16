rule sig_20161205_cb8712c580fe201127ac39185d7a89eb {
  meta:
    description = "datamaliciousorder - file 20161205_cb8712c580fe201127ac39185d7a89eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a79017ffad050008af9dc95e0b78f619286a2741f04a471de840b23ccf23e63"

  strings:
    $s1 = "function _Gy0(s) {var _HDh1 = new Date();_HDh1.setUTCFullYear(\"2003\");if (_HDh1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Gy0(s) {var _HDh1 = new Date();_HDh1.setUTCFullYear(\"2003\");if (_HDh1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Au6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}