rule sig_20161205_5950a37a2fc5b64d1eb8197361456db5 {
  meta:
    description = "datamaliciousorder - file 20161205_5950a37a2fc5b64d1eb8197361456db5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bd7bccbf3c43d87c72796880af237234cbc46cc54e84bf88381883a6fd22cfd"

  strings:
    $s1 = "function _QKc6(s) {var _HMk7 = new Date();_HMk7.setUTCFullYear(\"2003\");if (_HMk7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _QKc6(s) {var _HMk7 = new Date();_HMk7.setUTCFullYear(\"2003\");if (_HMk7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _KGb6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}