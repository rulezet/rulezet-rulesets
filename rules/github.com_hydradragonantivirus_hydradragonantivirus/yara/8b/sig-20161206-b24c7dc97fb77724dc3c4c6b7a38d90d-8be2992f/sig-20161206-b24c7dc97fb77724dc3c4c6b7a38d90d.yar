rule sig_20161206_b24c7dc97fb77724dc3c4c6b7a38d90d {
  meta:
    description = "datamaliciousorder - file 20161206_b24c7dc97fb77724dc3c4c6b7a38d90d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15605ed50040537229a2f28c145934a1ca151092fc6171e076d64694a346e288"

  strings:
    $s1 = "function _Cz6(s) {var _LMx9 = new Date();_LMx9.setUTCFullYear(\"2003\");if (_LMx9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Cz6(s) {var _LMx9 = new Date();_LMx9.setUTCFullYear(\"2003\");if (_LMx9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Od0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}