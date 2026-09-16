rule sig_20161206_ec1e8002623d9ef9aa6de0356e1a9cea {
  meta:
    description = "datamaliciousorder - file 20161206_ec1e8002623d9ef9aa6de0356e1a9cea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03bc0f9bad1cf8c0178c2dc7c7b02a3bc66dda35fd984b3dc177cdfe915234d5"

  strings:
    $s1 = "function _Pa3(s) {var _Mg8 = new Date();_Mg8.setUTCFullYear(\"2003\");if (_Mg8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Pa3(s) {var _Mg8 = new Date();_Mg8.setUTCFullYear(\"2003\");if (_Mg8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _BSu6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}