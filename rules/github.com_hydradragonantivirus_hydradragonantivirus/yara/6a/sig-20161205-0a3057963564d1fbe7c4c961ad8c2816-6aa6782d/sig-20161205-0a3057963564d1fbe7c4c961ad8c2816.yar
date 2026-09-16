rule sig_20161205_0a3057963564d1fbe7c4c961ad8c2816 {
  meta:
    description = "datamaliciousorder - file 20161205_0a3057963564d1fbe7c4c961ad8c2816.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10fc625dc1859a1f88b9cae2aae55e4268c027a65eff039d0266e855c75b6ca5"

  strings:
    $s1 = "function _Fe6(s) {var _Iu4 = new Date();_Iu4.setUTCFullYear(\"2003\");if (_Iu4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Fe6(s) {var _Iu4 = new Date();_Iu4.setUTCFullYear(\"2003\");if (_Iu4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _UBy5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}