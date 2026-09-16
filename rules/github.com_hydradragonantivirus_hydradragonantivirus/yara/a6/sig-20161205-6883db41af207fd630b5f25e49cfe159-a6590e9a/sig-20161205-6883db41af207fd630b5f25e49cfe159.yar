rule sig_20161205_6883db41af207fd630b5f25e49cfe159 {
  meta:
    description = "datamaliciousorder - file 20161205_6883db41af207fd630b5f25e49cfe159.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e35abc48c77b5e761b5c4dfed2de5d8f66e081083e6b9d5945999ee2703b1f2"

  strings:
    $s1 = "function _GHj8(s) {var _NPz1 = new Date();_NPz1.setUTCFullYear(\"2003\");if (_NPz1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _GHj8(s) {var _NPz1 = new Date();_NPz1.setUTCFullYear(\"2003\");if (_NPz1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ab6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}