rule sig_20161206_36aec8eb61c550778beb2261cce850f1 {
  meta:
    description = "datamaliciousorder - file 20161206_36aec8eb61c550778beb2261cce850f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "031573f3220b9d8f9030bf4a32eec81c736bfe2718c205da183618c249cbdb92"

  strings:
    $s1 = "function _SHj0(s) {var _An9 = new Date();_An9.setUTCFullYear(\"2003\");if (_An9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _SHj0(s) {var _An9 = new Date();_An9.setUTCFullYear(\"2003\");if (_An9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _KPk0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}