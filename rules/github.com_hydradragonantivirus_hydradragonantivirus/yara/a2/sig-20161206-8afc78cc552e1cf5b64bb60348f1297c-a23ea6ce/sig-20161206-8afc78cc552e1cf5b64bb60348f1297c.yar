rule sig_20161206_8afc78cc552e1cf5b64bb60348f1297c {
  meta:
    description = "datamaliciousorder - file 20161206_8afc78cc552e1cf5b64bb60348f1297c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d8bfebe38efa35b787fa86b5a6e1ef8ebdaa25d305ef55993108b82a5dcbc6f"

  strings:
    $s1 = "function _SYz5(s) {var _QPc1 = new Date();_QPc1.setUTCFullYear(\"2003\");if (_QPc1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _SYz5(s) {var _QPc1 = new Date();_QPc1.setUTCFullYear(\"2003\");if (_QPc1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _IQy5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}