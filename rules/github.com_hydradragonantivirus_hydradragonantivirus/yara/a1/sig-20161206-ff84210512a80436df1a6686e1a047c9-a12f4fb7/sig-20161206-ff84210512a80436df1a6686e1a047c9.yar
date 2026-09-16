rule sig_20161206_ff84210512a80436df1a6686e1a047c9 {
  meta:
    description = "datamaliciousorder - file 20161206_ff84210512a80436df1a6686e1a047c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37e1c573749881275a800be283ba1cc98c95805418fca435f3e266ce2e0d7c78"

  strings:
    $s1 = "var vTPd0 = new Function(\"s\", '{var vFMg7 = new Date();vFMg7[\"setUTCFullYear\"](\"2003\");if (vFMg7.getUTCFullYear().toString" ascii
    $s2 = "var vTPd0 = new Function(\"s\", '{var vFMg7 = new Date();vFMg7[\"setUTCFullYear\"](\"2003\");if (vFMg7.getUTCFullYear().toString" ascii
    $s3 = "function vGQd0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vIZz2 = s.split(\"##\"); return vIZz2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}