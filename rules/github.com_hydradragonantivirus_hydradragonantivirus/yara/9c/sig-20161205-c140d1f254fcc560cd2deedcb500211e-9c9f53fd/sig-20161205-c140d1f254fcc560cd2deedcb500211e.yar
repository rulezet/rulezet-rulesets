rule sig_20161205_c140d1f254fcc560cd2deedcb500211e {
  meta:
    description = "datamaliciousorder - file 20161205_c140d1f254fcc560cd2deedcb500211e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f06dfbc12dae278eb62266ca6150c80cc1e87a033846cf60a1c5468175715af2"

  strings:
    $s1 = "function _Bg3(s) {var _Nc8 = new Date();_Nc8.setUTCFullYear(\"2003\");if (_Nc8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Bg3(s) {var _Nc8 = new Date();_Nc8.setUTCFullYear(\"2003\");if (_Nc8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Vs7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}