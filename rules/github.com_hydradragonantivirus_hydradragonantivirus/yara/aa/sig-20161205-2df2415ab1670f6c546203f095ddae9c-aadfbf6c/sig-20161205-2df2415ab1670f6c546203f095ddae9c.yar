rule sig_20161205_2df2415ab1670f6c546203f095ddae9c {
  meta:
    description = "datamaliciousorder - file 20161205_2df2415ab1670f6c546203f095ddae9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c658a620977416fac16e9885e3b21742645bd5635b52d13da87f0152911c205b"

  strings:
    $s1 = "function _DPw1(s) {var _Xz3 = new Date();_Xz3.setUTCFullYear(\"2003\");if (_Xz3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _DPw1(s) {var _Xz3 = new Date();_Xz3.setUTCFullYear(\"2003\");if (_Xz3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Jg7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}