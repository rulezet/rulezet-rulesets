rule sig_20161206_a9f0c364d133886f3b321ae34dbdbff0 {
  meta:
    description = "datamaliciousorder - file 20161206_a9f0c364d133886f3b321ae34dbdbff0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eab6d1b70f3b2cfa4fee4a9b9c0003ba997336a800578013b2067356a75f82a4"

  strings:
    $s1 = "var vNi4 = new Function(\"s\", '{var vXc3 = new Date();vXc3[\"setUTCFullYear\"](\"2003\");if (vXc3.getUTCFullYear().toString(10)" ascii
    $s2 = "var vNi4 = new Function(\"s\", '{var vXc3 = new Date();vXc3[\"setUTCFullYear\"](\"2003\");if (vXc3.getUTCFullYear().toString(10)" ascii
    $s3 = "function vTi2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vIc5 = s.split(\"##\"); return vIc5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}