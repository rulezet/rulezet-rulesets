rule sig_20161205_b480a825a65e1432de67b4c458d2715c {
  meta:
    description = "datamaliciousorder - file 20161205_b480a825a65e1432de67b4c458d2715c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d576d3f54ee4a6e3c52ccf201320055565b98592e6b295526695a6159c5a5e52"

  strings:
    $s1 = "function _MYn6(s) {var _TZc8 = new Date();_TZc8.setUTCFullYear(\"2003\");if (_TZc8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _MYn6(s) {var _TZc8 = new Date();_TZc8.setUTCFullYear(\"2003\");if (_TZc8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Wm5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}