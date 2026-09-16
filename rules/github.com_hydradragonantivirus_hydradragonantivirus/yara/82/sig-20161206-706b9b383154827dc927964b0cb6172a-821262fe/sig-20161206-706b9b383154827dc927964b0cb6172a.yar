rule sig_20161206_706b9b383154827dc927964b0cb6172a {
  meta:
    description = "datamaliciousorder - file 20161206_706b9b383154827dc927964b0cb6172a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e28a7b923d71cf3057d6d3c1d94716ca5e9c31a14c32577578307b8c315c47bc"

  strings:
    $s1 = "function _Dw5(s) {var _CFn4 = new Date();_CFn4.setUTCFullYear(\"2003\");if (_CFn4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Dw5(s) {var _CFn4 = new Date();_CFn4.setUTCFullYear(\"2003\");if (_CFn4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _UDl0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}