rule sig_20161205_ebde022527a64cfa761d6fb686e39bed {
  meta:
    description = "datamaliciousorder - file 20161205_ebde022527a64cfa761d6fb686e39bed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8367fdfd60bf3b1669a1604e6d19ea183548b1589469197b36affc1a695005b4"

  strings:
    $s1 = "function _Ki7(s) {var _Fe7 = new Date();_Fe7.setUTCFullYear(\"2003\");if (_Fe7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ki7(s) {var _Fe7 = new Date();_Fe7.setUTCFullYear(\"2003\");if (_Fe7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _OHb8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}