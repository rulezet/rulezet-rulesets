rule sig_20161206_b98b58dc7f93d700f05086f504363848 {
  meta:
    description = "datamaliciousorder - file 20161206_b98b58dc7f93d700f05086f504363848.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96f5c81a8fcb3842efbc4f1097c71febacc444906955b3a4fc1159343f01524d"

  strings:
    $s1 = "var vYm2 = new Function(\"s\", '{var vERt5 = new Date();vERt5[\"setUTCFullYear\"](\"2003\");if (vERt5.getUTCFullYear().toString(" ascii
    $s2 = "var vYm2 = new Function(\"s\", '{var vERt5 = new Date();vERt5[\"setUTCFullYear\"](\"2003\");if (vERt5.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vEr9 = s.split(\"##\"); return vEr9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vDZb0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}