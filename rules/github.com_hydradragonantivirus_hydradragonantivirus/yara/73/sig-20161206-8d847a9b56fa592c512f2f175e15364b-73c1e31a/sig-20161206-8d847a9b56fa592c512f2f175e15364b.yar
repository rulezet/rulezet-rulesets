rule sig_20161206_8d847a9b56fa592c512f2f175e15364b {
  meta:
    description = "datamaliciousorder - file 20161206_8d847a9b56fa592c512f2f175e15364b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92268e05306c014eed75616cc75a1cc666a98ca524ba9f6ca4a9c717a0f7eac7"

  strings:
    $s1 = "function _Mt6(s) {var _Ny4 = new Date();_Ny4.setUTCFullYear(\"2003\");if (_Ny4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Mt6(s) {var _Ny4 = new Date();_Ny4.setUTCFullYear(\"2003\");if (_Ny4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _LVp3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}