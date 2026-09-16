rule sig_20161205_9895346d4f38466aad3dd733e2b078e8 {
  meta:
    description = "datamaliciousorder - file 20161205_9895346d4f38466aad3dd733e2b078e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ac23b7071777815923fed63c8fd358fd8d52269a10669fa7d9f0481a90cd9e4"

  strings:
    $s1 = "function _Wp4(s) {var _Oc4 = new Date();_Oc4.setUTCFullYear(\"2003\");if (_Oc4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Wp4(s) {var _Oc4 = new Date();_Oc4.setUTCFullYear(\"2003\");if (_Oc4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _MBy3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}