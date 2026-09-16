rule sig_20161205_6fff235160f391926d6182c9f4ff0b3c {
  meta:
    description = "datamaliciousorder - file 20161205_6fff235160f391926d6182c9f4ff0b3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4b7bf4853557f3beb8e3f2bdec1ac0a52557d897b30ea897476742fad601e75"

  strings:
    $s1 = "function _Si8(s) {var _MRf0 = new Date();_MRf0.setUTCFullYear(\"2003\");if (_MRf0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Si8(s) {var _MRf0 = new Date();_MRf0.setUTCFullYear(\"2003\");if (_MRf0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _EAj1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}