rule sig_20161206_3e495fad4e1b615a0a1c5fa81152f080 {
  meta:
    description = "datamaliciousorder - file 20161206_3e495fad4e1b615a0a1c5fa81152f080.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d297f680c8f1bb2b79fa25f51c5377a8a60a4195e02e2c7b3ec511288480383"

  strings:
    $s1 = "var vYCc0 = new Function(\"s\", '{var vPJz7 = new Date();vPJz7[\"setUTCFullYear\"](\"2003\");if (vPJz7.getUTCFullYear().toString" ascii
    $s2 = "var vYCc0 = new Function(\"s\", '{var vPJz7 = new Date();vPJz7[\"setUTCFullYear\"](\"2003\");if (vPJz7.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vHt4 = s.split(\"##\"); return vHt4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vHUb6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}