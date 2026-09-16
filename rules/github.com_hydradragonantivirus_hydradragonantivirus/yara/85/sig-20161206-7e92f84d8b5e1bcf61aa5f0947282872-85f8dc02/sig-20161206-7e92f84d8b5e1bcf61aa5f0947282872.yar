rule sig_20161206_7e92f84d8b5e1bcf61aa5f0947282872 {
  meta:
    description = "datamaliciousorder - file 20161206_7e92f84d8b5e1bcf61aa5f0947282872.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d04ba778784818b93fd49e5c5b237521d649d0247333dc818f707a0a81e48fd6"

  strings:
    $s1 = "function _LCn7(s) {var _UMe4 = new Date();_UMe4.setUTCFullYear(\"2003\");if (_UMe4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _LCn7(s) {var _UMe4 = new Date();_UMe4.setUTCFullYear(\"2003\");if (_UMe4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _TVr2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}