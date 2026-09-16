rule sig_20161205_4250cc859a3eb0a7fbf9a0f61660f0ec {
  meta:
    description = "datamaliciousorder - file 20161205_4250cc859a3eb0a7fbf9a0f61660f0ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98be7ad8a35207a7987208aacb1addf8c4e87e892f4780ca92835c7d2b80a7ce"

  strings:
    $s1 = "function _Jd8(s) {var _Wr6 = new Date();_Wr6.setUTCFullYear(\"2003\");if (_Wr6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Jd8(s) {var _Wr6 = new Date();_Wr6.setUTCFullYear(\"2003\");if (_Wr6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _QCy2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}