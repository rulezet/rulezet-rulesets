rule sig_20161205_8fe3dccd0fb5ce3481c2bad66f1c6daf {
  meta:
    description = "datamaliciousorder - file 20161205_8fe3dccd0fb5ce3481c2bad66f1c6daf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f8cba69bd48204c5a07794fbbff2f65ae54468c76dccd0896a05e5d410307fa"

  strings:
    $s1 = "function _Ee4(s) {var _Jj5 = new Date();_Jj5.setUTCFullYear(\"2003\");if (_Jj5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ee4(s) {var _Jj5 = new Date();_Jj5.setUTCFullYear(\"2003\");if (_Jj5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _VEp7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}