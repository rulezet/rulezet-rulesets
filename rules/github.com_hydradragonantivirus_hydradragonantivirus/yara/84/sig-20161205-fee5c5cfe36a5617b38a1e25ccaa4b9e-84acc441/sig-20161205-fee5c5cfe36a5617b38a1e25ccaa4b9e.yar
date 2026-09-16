rule sig_20161205_fee5c5cfe36a5617b38a1e25ccaa4b9e {
  meta:
    description = "datamaliciousorder - file 20161205_fee5c5cfe36a5617b38a1e25ccaa4b9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bb8a7619dcccb5604750f0d53c83f219bd52f2f71b79900154f2c1ff99fb387"

  strings:
    $s1 = "function _TNp5(s) {var _Ix0 = new Date();_Ix0.setUTCFullYear(\"2003\");if (_Ix0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _TNp5(s) {var _Ix0 = new Date();_Ix0.setUTCFullYear(\"2003\");if (_Ix0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _WWk8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}