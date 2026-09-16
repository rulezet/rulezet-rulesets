rule sig_20161205_bfa57b8f7177f3a8cc50d70e1c55243e {
  meta:
    description = "datamaliciousorder - file 20161205_bfa57b8f7177f3a8cc50d70e1c55243e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c10b8987c08b9a3025f59a46e886ca67987524d8138e3f25a8273cddf4d78350"

  strings:
    $s1 = "function _Bn2(s) {var _Iw4 = new Date();_Iw4.setUTCFullYear(\"2003\");if (_Iw4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Bn2(s) {var _Iw4 = new Date();_Iw4.setUTCFullYear(\"2003\");if (_Iw4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _KOm2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}