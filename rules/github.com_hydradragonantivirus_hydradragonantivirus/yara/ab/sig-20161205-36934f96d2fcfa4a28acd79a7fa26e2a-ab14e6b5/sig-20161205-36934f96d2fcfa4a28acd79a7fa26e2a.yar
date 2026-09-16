rule sig_20161205_36934f96d2fcfa4a28acd79a7fa26e2a {
  meta:
    description = "datamaliciousorder - file 20161205_36934f96d2fcfa4a28acd79a7fa26e2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87a909f1fc3514f061594090fc1ac00440c70006a2918cc669a8c054278e1251"

  strings:
    $s1 = "function _JDo0(s) {var _CRm5 = new Date();_CRm5.setUTCFullYear(\"2003\");if (_CRm5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _JDo0(s) {var _CRm5 = new Date();_CRm5.setUTCFullYear(\"2003\");if (_CRm5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Bt3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}