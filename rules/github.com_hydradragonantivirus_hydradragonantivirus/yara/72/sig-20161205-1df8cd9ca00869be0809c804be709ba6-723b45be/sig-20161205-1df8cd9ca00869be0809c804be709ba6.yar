rule sig_20161205_1df8cd9ca00869be0809c804be709ba6 {
  meta:
    description = "datamaliciousorder - file 20161205_1df8cd9ca00869be0809c804be709ba6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7756b506d4cfd43b4e01fda21c8f4a73cd2df0f03db82ea45917474d1e832811"

  strings:
    $s1 = "function _Rp9(s) {var _IDx7 = new Date();_IDx7.setUTCFullYear(\"2003\");if (_IDx7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Rp9(s) {var _IDx7 = new Date();_IDx7.setUTCFullYear(\"2003\");if (_IDx7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ys6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}