rule sig_20161205_afc3d1242f5c2b17360ffaf8798fe9f9 {
  meta:
    description = "datamaliciousorder - file 20161205_afc3d1242f5c2b17360ffaf8798fe9f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0055232d381a7d766d7793cfed8a17be0bb28e42134674606ca030bb0cb91929"

  strings:
    $s1 = "function _Jp1(s) {var _RIr2 = new Date();_RIr2.setUTCFullYear(\"2003\");if (_RIr2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Jp1(s) {var _RIr2 = new Date();_RIr2.setUTCFullYear(\"2003\");if (_RIr2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Vj1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}