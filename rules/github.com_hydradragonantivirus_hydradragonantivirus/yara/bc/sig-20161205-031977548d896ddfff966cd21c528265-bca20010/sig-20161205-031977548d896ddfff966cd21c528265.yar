rule sig_20161205_031977548d896ddfff966cd21c528265 {
  meta:
    description = "datamaliciousorder - file 20161205_031977548d896ddfff966cd21c528265.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18b32102f2ed9fc1ebbd2082d7368c722dd179fb8e3440ca7d14d7ca31151724"

  strings:
    $s1 = "function _Np7(s) {var _RGj6 = new Date();_RGj6.setUTCFullYear(\"2003\");if (_RGj6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Np7(s) {var _RGj6 = new Date();_RGj6.setUTCFullYear(\"2003\");if (_RGj6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _SJw6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}