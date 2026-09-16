rule sig_20161206_7bf875a267f657da18bd81bf2791d3c9 {
  meta:
    description = "datamaliciousorder - file 20161206_7bf875a267f657da18bd81bf2791d3c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daa57bc33bc4822b361e3e83b0bf524e5fff801387e3efd9c74e552d37e0e97f"

  strings:
    $s1 = "function _Zl7(s) {var _Xs3 = new Date();_Xs3.setUTCFullYear(\"2003\");if (_Xs3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Zl7(s) {var _Xs3 = new Date();_Xs3.setUTCFullYear(\"2003\");if (_Xs3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Uo9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}