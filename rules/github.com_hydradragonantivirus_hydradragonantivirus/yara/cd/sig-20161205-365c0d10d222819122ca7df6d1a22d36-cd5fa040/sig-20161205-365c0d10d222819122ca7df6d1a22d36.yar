rule sig_20161205_365c0d10d222819122ca7df6d1a22d36 {
  meta:
    description = "datamaliciousorder - file 20161205_365c0d10d222819122ca7df6d1a22d36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43576701d521751b89ec1c796cc5766c74bbe6a8200d378b3ab195d2c8a74279"

  strings:
    $s1 = "function _GVw5(s) {var _USw6 = new Date();_USw6.setUTCFullYear(\"2003\");if (_USw6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _GVw5(s) {var _USw6 = new Date();_USw6.setUTCFullYear(\"2003\");if (_USw6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _TXa3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}