rule sig_20161205_658081ea27d337b84c2ffa842f1136bc {
  meta:
    description = "datamaliciousorder - file 20161205_658081ea27d337b84c2ffa842f1136bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea304a2354ac0ec453dcf7f65b15716bc6c18b3365222339d6910b1fa28cdae3"

  strings:
    $s1 = "function _LAb1(s) {var _Mu6 = new Date();_Mu6.setUTCFullYear(\"2003\");if (_Mu6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LAb1(s) {var _Mu6 = new Date();_Mu6.setUTCFullYear(\"2003\");if (_Mu6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Qx7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}