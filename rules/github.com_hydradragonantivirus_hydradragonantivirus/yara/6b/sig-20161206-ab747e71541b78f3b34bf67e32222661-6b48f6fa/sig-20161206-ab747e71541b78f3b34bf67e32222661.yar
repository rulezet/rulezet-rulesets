rule sig_20161206_ab747e71541b78f3b34bf67e32222661 {
  meta:
    description = "datamaliciousorder - file 20161206_ab747e71541b78f3b34bf67e32222661.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43591383c7b24c76f93ef98e5b49bdec3fdd11909d65db7ee0e639954f8fb49a"

  strings:
    $s1 = "function _No0(s) {var _DPj7 = new Date();_DPj7.setUTCFullYear(\"2003\");if (_DPj7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _No0(s) {var _DPj7 = new Date();_DPj7.setUTCFullYear(\"2003\");if (_DPj7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _LHv7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}