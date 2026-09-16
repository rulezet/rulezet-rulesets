rule sig_20161206_5d20896b869ca74e46338f18a5c47b36 {
  meta:
    description = "datamaliciousorder - file 20161206_5d20896b869ca74e46338f18a5c47b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eaf95091280ce4d42a4c1e990831cb213eb8a0d74bc854bd994c4e7a79a09603"

  strings:
    $s1 = "function _Od9(s) {var _Mi9 = new Date();_Mi9.setUTCFullYear(\"2003\");if (_Mi9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Od9(s) {var _Mi9 = new Date();_Mi9.setUTCFullYear(\"2003\");if (_Mi9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _XOx6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}