rule sig_20161206_ba8199222746b42ff16762a2bd5597a9 {
  meta:
    description = "datamaliciousorder - file 20161206_ba8199222746b42ff16762a2bd5597a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f7db81db5351aabb07734c09896ae89277544daf671544b838d83019f11f4f7"

  strings:
    $s1 = "function _Bh3(s) {var _Kc6 = new Date();_Kc6.setUTCFullYear(\"2003\");if (_Kc6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Bh3(s) {var _Kc6 = new Date();_Kc6.setUTCFullYear(\"2003\");if (_Kc6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Yf8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}