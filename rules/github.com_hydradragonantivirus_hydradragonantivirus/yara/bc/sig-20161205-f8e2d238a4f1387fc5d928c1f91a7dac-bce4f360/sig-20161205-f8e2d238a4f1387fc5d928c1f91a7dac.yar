rule sig_20161205_f8e2d238a4f1387fc5d928c1f91a7dac {
  meta:
    description = "datamaliciousorder - file 20161205_f8e2d238a4f1387fc5d928c1f91a7dac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a5980cde178048334efb78a34e5ce8f2dd215299ece2e560b6c4b820fe6fe9f"

  strings:
    $s1 = "function _KCk3(s) {var _Fr3 = new Date();_Fr3.setUTCFullYear(\"2003\");if (_Fr3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _KCk3(s) {var _Fr3 = new Date();_Fr3.setUTCFullYear(\"2003\");if (_Fr3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ed0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}