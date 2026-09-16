rule sig_20161205_9abf534ecf86db58db4426b794f18f54 {
  meta:
    description = "datamaliciousorder - file 20161205_9abf534ecf86db58db4426b794f18f54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc747048ef9a829844d5b28c08e33450da68d530434386f26b9503fdafe1b4c3"

  strings:
    $s1 = "function _Wf8(s) {var _DWi1 = new Date();_DWi1.setUTCFullYear(\"2003\");if (_DWi1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Wf8(s) {var _DWi1 = new Date();_DWi1.setUTCFullYear(\"2003\");if (_DWi1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _TCh5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}