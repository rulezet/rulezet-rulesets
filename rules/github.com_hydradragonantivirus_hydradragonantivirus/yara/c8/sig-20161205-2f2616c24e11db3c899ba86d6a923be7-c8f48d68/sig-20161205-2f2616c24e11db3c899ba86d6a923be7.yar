rule sig_20161205_2f2616c24e11db3c899ba86d6a923be7 {
  meta:
    description = "datamaliciousorder - file 20161205_2f2616c24e11db3c899ba86d6a923be7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e3523c98b83c4b4246588f5fad57a60fed4e7f13a91ab44790db6a1db61d62e"

  strings:
    $s1 = "function _Ef5(s) {var _Qs0 = new Date();_Qs0.setUTCFullYear(\"2003\");if (_Qs0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ef5(s) {var _Qs0 = new Date();_Qs0.setUTCFullYear(\"2003\");if (_Qs0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _BRs8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}