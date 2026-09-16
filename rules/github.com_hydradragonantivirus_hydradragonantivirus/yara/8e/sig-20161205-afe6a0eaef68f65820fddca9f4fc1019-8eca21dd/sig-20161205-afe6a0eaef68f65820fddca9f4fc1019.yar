rule sig_20161205_afe6a0eaef68f65820fddca9f4fc1019 {
  meta:
    description = "datamaliciousorder - file 20161205_afe6a0eaef68f65820fddca9f4fc1019.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "313073951b1f9a68ffde7008dbb64970b59d630956a109860b6d2c6aa010f186"

  strings:
    $s1 = "function _YAl2(s) {var _FZe7 = new Date();_FZe7.setUTCFullYear(\"2003\");if (_FZe7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YAl2(s) {var _FZe7 = new Date();_FZe7.setUTCFullYear(\"2003\");if (_FZe7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _HIc5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}