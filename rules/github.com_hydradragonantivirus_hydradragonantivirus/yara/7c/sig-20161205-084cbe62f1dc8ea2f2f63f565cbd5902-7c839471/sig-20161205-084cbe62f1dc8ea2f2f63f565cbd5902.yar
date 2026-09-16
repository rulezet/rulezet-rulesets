rule sig_20161205_084cbe62f1dc8ea2f2f63f565cbd5902 {
  meta:
    description = "datamaliciousorder - file 20161205_084cbe62f1dc8ea2f2f63f565cbd5902.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e081f9565c55cd7f18749e7d84650ba642650df8b8b2fa023961f256d2dd497f"

  strings:
    $s1 = "function _GUt3(s) {var _Za7 = new Date();_Za7.setUTCFullYear(\"2003\");if (_Za7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _GUt3(s) {var _Za7 = new Date();_Za7.setUTCFullYear(\"2003\");if (_Za7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _RTb7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}