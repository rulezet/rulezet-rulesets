rule sig_20161206_d60278e838c4695b75d27417e1c9fbf8 {
  meta:
    description = "datamaliciousorder - file 20161206_d60278e838c4695b75d27417e1c9fbf8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bd31d3efaf59afaf097c5430b0aea826de342e4c708f3fd3299c042012e72ee"

  strings:
    $s1 = "function _Hf6(s) {var _Pp3 = new Date();_Pp3.setUTCFullYear(\"2003\");if (_Pp3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Hf6(s) {var _Pp3 = new Date();_Pp3.setUTCFullYear(\"2003\");if (_Pp3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Mj5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}