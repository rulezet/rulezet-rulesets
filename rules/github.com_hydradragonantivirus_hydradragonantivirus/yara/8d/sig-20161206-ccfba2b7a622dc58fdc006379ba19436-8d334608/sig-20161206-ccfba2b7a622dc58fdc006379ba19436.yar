rule sig_20161206_ccfba2b7a622dc58fdc006379ba19436 {
  meta:
    description = "datamaliciousorder - file 20161206_ccfba2b7a622dc58fdc006379ba19436.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "006e153c3b0a6ba216a5cc2246dc54ba30a74fa4f46ea1e2cf02666c35cdd749"

  strings:
    $s1 = "function _ZMa6(s) {var _STb2 = new Date();_STb2.setUTCFullYear(\"2003\");if (_STb2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ZMa6(s) {var _STb2 = new Date();_STb2.setUTCFullYear(\"2003\");if (_STb2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _XRi2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}