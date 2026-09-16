rule sig_20161206_ef8943b3fb6cdea5fd7b8fa159193b4b {
  meta:
    description = "datamaliciousorder - file 20161206_ef8943b3fb6cdea5fd7b8fa159193b4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b3fec3574d280110761d380f1b2ea056833c2f547e9c49c85a13282b50f91e2"

  strings:
    $s1 = "function _Gl5(s) {var _Qb3 = new Date();_Qb3.setUTCFullYear(\"2003\");if (_Qb3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Gl5(s) {var _Qb3 = new Date();_Qb3.setUTCFullYear(\"2003\");if (_Qb3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _LLo8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}