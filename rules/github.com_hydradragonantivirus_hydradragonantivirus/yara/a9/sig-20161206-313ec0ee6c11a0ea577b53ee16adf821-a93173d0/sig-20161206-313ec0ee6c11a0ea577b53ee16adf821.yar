rule sig_20161206_313ec0ee6c11a0ea577b53ee16adf821 {
  meta:
    description = "datamaliciousorder - file 20161206_313ec0ee6c11a0ea577b53ee16adf821.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f40498f5245b0aa68a0cd849743af9359e4a463cf225034b01a34a55af233e5"

  strings:
    $s1 = "function _Ci7(s) {var _Tt5 = new Date();_Tt5.setUTCFullYear(\"2003\");if (_Tt5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ci7(s) {var _Tt5 = new Date();_Tt5.setUTCFullYear(\"2003\");if (_Tt5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _VKp3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}