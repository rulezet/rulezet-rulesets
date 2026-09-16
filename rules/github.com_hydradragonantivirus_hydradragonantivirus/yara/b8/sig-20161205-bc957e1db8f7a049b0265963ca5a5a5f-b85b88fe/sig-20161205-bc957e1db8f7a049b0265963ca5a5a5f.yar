rule sig_20161205_bc957e1db8f7a049b0265963ca5a5a5f {
  meta:
    description = "datamaliciousorder - file 20161205_bc957e1db8f7a049b0265963ca5a5a5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b46227f1c670ceeba20d4933b0be4d788e461f08315b26a80227bef3755b8b09"

  strings:
    $s1 = "function _ZXn4(s) {var _Lg4 = new Date();_Lg4.setUTCFullYear(\"2003\");if (_Lg4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ZXn4(s) {var _Lg4 = new Date();_Lg4.setUTCFullYear(\"2003\");if (_Lg4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ix3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}