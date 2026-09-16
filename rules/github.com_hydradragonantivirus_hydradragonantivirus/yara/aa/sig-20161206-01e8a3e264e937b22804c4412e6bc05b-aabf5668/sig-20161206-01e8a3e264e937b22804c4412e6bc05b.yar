rule sig_20161206_01e8a3e264e937b22804c4412e6bc05b {
  meta:
    description = "datamaliciousorder - file 20161206_01e8a3e264e937b22804c4412e6bc05b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50f7b4bf141222290c58ef21ebd2df5490800ed8f6999aea44e68dd3fc2c2c6f"

  strings:
    $s1 = "var vLNj2 = new Function(\"s\", '{var vUIf1 = new Date();vUIf1[\"setUTCFullYear\"](\"2003\");if (vUIf1.getUTCFullYear().toString" ascii
    $s2 = "var vLNj2 = new Function(\"s\", '{var vUIf1 = new Date();vUIf1[\"setUTCFullYear\"](\"2003\");if (vUIf1.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vIDi7 = s.split(\"##\"); return vIDi7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vRRo2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}