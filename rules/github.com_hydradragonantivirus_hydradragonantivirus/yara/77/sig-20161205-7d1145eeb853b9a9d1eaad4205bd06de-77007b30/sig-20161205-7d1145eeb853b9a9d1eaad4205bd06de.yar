rule sig_20161205_7d1145eeb853b9a9d1eaad4205bd06de {
  meta:
    description = "datamaliciousorder - file 20161205_7d1145eeb853b9a9d1eaad4205bd06de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d25ddc007b0af3b105f797f23120b795ea49a438ab1c10c44938a5e122524207"

  strings:
    $s1 = "function _Hc3(s) {var _Dm8 = new Date();_Dm8.setUTCFullYear(\"2003\");if (_Dm8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Hc3(s) {var _Dm8 = new Date();_Dm8.setUTCFullYear(\"2003\");if (_Dm8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _GTp8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}