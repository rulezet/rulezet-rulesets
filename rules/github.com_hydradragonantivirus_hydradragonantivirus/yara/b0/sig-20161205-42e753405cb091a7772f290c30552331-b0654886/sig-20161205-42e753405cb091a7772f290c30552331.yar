rule sig_20161205_42e753405cb091a7772f290c30552331 {
  meta:
    description = "datamaliciousorder - file 20161205_42e753405cb091a7772f290c30552331.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a54f398b1e32d8f9c3338ca03cabf145aed835ce2082a9e51062498dea0244c"

  strings:
    $s1 = "function _TQo7(s) {var _AVt8 = new Date();_AVt8.setUTCFullYear(\"2003\");if (_AVt8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _TQo7(s) {var _AVt8 = new Date();_AVt8.setUTCFullYear(\"2003\");if (_AVt8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Zw5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}