rule sig_20161205_40da239b4a46a1509638576a02a904ce {
  meta:
    description = "datamaliciousorder - file 20161205_40da239b4a46a1509638576a02a904ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c4eb54c687447ad965b19a6ab38bb661793fd9ce3c653b1ec9356d947257bfb"

  strings:
    $s1 = "function _Nx0(s) {var _NUx9 = new Date();_NUx9.setUTCFullYear(\"2003\");if (_NUx9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Nx0(s) {var _NUx9 = new Date();_NUx9.setUTCFullYear(\"2003\");if (_NUx9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _MNe9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}