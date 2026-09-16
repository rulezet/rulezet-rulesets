rule sig_20161206_38c8761de2e13f895376362241f9e1fe {
  meta:
    description = "datamaliciousorder - file 20161206_38c8761de2e13f895376362241f9e1fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03aae9a8efaa6eedf33afb625c31ea7f37829d9955e57b7b280eb1aeae4035f5"

  strings:
    $s1 = "function _Pr1(s) {var _Hx3 = new Date();_Hx3.setUTCFullYear(\"2003\");if (_Hx3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Pr1(s) {var _Hx3 = new Date();_Hx3.setUTCFullYear(\"2003\");if (_Hx3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Fo0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}