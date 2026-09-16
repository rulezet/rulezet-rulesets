rule sig_20161205_f6d2300c16754f5cd8cd876d590fca39 {
  meta:
    description = "datamaliciousorder - file 20161205_f6d2300c16754f5cd8cd876d590fca39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a85d88e70471e418dc9a5c88a802fc2e39b56d74cd10d455f0380546d4a6409e"

  strings:
    $s1 = "function _Xz1(s) {var _RSa8 = new Date();_RSa8.setUTCFullYear(\"2003\");if (_RSa8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Xz1(s) {var _RSa8 = new Date();_RSa8.setUTCFullYear(\"2003\");if (_RSa8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ym9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}