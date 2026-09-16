rule sig_20161205_71d0831cbe5ea35616570ac08a0fc07a {
  meta:
    description = "datamaliciousorder - file 20161205_71d0831cbe5ea35616570ac08a0fc07a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f9ed370e7a795ff32411790a81c12e505b261242189a1fa95a395b8f4c9a84f"

  strings:
    $s1 = "function _Gp4(s) {var _Uc4 = new Date();_Uc4.setUTCFullYear(\"2003\");if (_Uc4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Gp4(s) {var _Uc4 = new Date();_Uc4.setUTCFullYear(\"2003\");if (_Uc4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _QBq5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}