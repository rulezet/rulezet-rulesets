rule sig_20161205_9e253472a00f17944c89ee6eda717ea4 {
  meta:
    description = "datamaliciousorder - file 20161205_9e253472a00f17944c89ee6eda717ea4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d71a8ec68f9a96af31e6af7f11ebc6dd471966b12520f42f104f0f1f66ce8ad"

  strings:
    $s1 = "function _LXa5(s) {var _Tq6 = new Date();_Tq6.setUTCFullYear(\"2003\");if (_Tq6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LXa5(s) {var _Tq6 = new Date();_Tq6.setUTCFullYear(\"2003\");if (_Tq6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Vy1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}