rule sig_20161205_a05fc2ffb92cc796d4d4e5700ab4c822 {
  meta:
    description = "datamaliciousorder - file 20161205_a05fc2ffb92cc796d4d4e5700ab4c822.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "580f93091cef182b4dbe1572893a01ab140bcecbb47923023cae4c35535d1f22"

  strings:
    $s1 = "function _OOn5(s) {var _VNn4 = new Date();_VNn4.setUTCFullYear(\"2003\");if (_VNn4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _OOn5(s) {var _VNn4 = new Date();_VNn4.setUTCFullYear(\"2003\");if (_VNn4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Hk3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}