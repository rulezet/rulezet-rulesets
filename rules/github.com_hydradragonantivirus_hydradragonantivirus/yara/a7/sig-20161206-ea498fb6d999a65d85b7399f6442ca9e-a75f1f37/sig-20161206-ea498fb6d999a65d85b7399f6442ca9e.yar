rule sig_20161206_ea498fb6d999a65d85b7399f6442ca9e {
  meta:
    description = "datamaliciousorder - file 20161206_ea498fb6d999a65d85b7399f6442ca9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba0550031097e9568f2a5901ae687c335a36b76c009042fcf55f7c29b57189f9"

  strings:
    $s1 = "var vKa4 = new Function(\"s\", '{var vFMd1 = new Date();vFMd1[\"setUTCFullYear\"](\"2003\");if (vFMd1.getUTCFullYear().toString(" ascii
    $s2 = "var vKa4 = new Function(\"s\", '{var vFMd1 = new Date();vFMd1[\"setUTCFullYear\"](\"2003\");if (vFMd1.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vJw4 = s.split(\"##\"); return vJw4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vWYm5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}