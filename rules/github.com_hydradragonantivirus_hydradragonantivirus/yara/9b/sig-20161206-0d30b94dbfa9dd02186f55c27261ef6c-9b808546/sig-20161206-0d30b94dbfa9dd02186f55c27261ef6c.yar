rule sig_20161206_0d30b94dbfa9dd02186f55c27261ef6c {
  meta:
    description = "datamaliciousorder - file 20161206_0d30b94dbfa9dd02186f55c27261ef6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68bce764997e705a20b5590f55ca37694dcff878c9e134d21ce0acb843e562fa"

  strings:
    $s1 = "var vMYm5 = new Function(\"s\", '{var vQp0 = new Date();vQp0[\"setUTCFullYear\"](\"2003\");if (vQp0.getUTCFullYear().toString(10" ascii
    $s2 = "var vMYm5 = new Function(\"s\", '{var vQp0 = new Date();vQp0[\"setUTCFullYear\"](\"2003\");if (vQp0.getUTCFullYear().toString(10" ascii
    $s3 = "function vNl6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vOf9 = s.split(\"##\"); return vOf9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}