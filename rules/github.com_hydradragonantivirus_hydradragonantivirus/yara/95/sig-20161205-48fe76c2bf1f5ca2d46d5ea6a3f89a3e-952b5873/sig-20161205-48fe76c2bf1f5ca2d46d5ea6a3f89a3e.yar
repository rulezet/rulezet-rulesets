rule sig_20161205_48fe76c2bf1f5ca2d46d5ea6a3f89a3e {
  meta:
    description = "datamaliciousorder - file 20161205_48fe76c2bf1f5ca2d46d5ea6a3f89a3e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fef84873481b24c2f96f6adf3be47416fd87034a7c5cab35b01763c7a0eec5e7"

  strings:
    $s1 = "function _FZy7(s) {var _Gk4 = new Date();_Gk4.setUTCFullYear(\"2003\");if (_Gk4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _FZy7(s) {var _Gk4 = new Date();_Gk4.setUTCFullYear(\"2003\");if (_Gk4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Au9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}