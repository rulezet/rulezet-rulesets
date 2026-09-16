rule sig_20161205_5a6e0a1efe9ff90aa923259c133017cf {
  meta:
    description = "datamaliciousorder - file 20161205_5a6e0a1efe9ff90aa923259c133017cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ad06b8e9c2cad0e71ef99a5df069d4c1688f6d4b4b2a6116ef1893f914cfdc5"

  strings:
    $s1 = "function _UBt5(s) {var _Mi2 = new Date();_Mi2.setUTCFullYear(\"2003\");if (_Mi2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _UBt5(s) {var _Mi2 = new Date();_Mi2.setUTCFullYear(\"2003\");if (_Mi2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ck5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}