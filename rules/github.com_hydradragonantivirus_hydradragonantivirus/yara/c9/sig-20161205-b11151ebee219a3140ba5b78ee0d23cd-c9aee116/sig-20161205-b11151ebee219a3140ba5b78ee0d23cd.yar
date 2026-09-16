rule sig_20161205_b11151ebee219a3140ba5b78ee0d23cd {
  meta:
    description = "datamaliciousorder - file 20161205_b11151ebee219a3140ba5b78ee0d23cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3788a0198990f230055f57d6a9e5d9266a516377ebbceb9faf06df2c05c7c08"

  strings:
    $s1 = "function _QXp3(s) {var _Wk2 = new Date();_Wk2.setUTCFullYear(\"2003\");if (_Wk2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _QXp3(s) {var _Wk2 = new Date();_Wk2.setUTCFullYear(\"2003\");if (_Wk2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Lk2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}