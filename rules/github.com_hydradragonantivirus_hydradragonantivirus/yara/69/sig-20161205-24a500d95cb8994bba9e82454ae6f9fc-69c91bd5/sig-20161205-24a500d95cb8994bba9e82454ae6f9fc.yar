rule sig_20161205_24a500d95cb8994bba9e82454ae6f9fc {
  meta:
    description = "datamaliciousorder - file 20161205_24a500d95cb8994bba9e82454ae6f9fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c72158d0ac7bd81ed69997a5e15d77759fbe74c6c19eb0b98523812152047f9c"

  strings:
    $s1 = "function _Hp8(s) {var _Br5 = new Date();_Br5.setUTCFullYear(\"2003\");if (_Br5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Hp8(s) {var _Br5 = new Date();_Br5.setUTCFullYear(\"2003\");if (_Br5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Wi4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}