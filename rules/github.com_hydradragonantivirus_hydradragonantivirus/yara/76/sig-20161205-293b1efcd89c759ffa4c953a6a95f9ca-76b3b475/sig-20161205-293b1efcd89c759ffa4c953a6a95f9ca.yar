rule sig_20161205_293b1efcd89c759ffa4c953a6a95f9ca {
  meta:
    description = "datamaliciousorder - file 20161205_293b1efcd89c759ffa4c953a6a95f9ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c817352535c7e124705692c7af9cff54235282739a890e5d8a924aedfe94db9"

  strings:
    $s1 = "function _Xw7(s) {var _UPf2 = new Date();_UPf2.setUTCFullYear(\"2003\");if (_UPf2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Xw7(s) {var _UPf2 = new Date();_UPf2.setUTCFullYear(\"2003\");if (_UPf2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Wp5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}