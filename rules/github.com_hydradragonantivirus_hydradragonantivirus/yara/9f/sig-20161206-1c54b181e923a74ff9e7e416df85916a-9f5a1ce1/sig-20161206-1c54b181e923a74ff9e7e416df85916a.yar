rule sig_20161206_1c54b181e923a74ff9e7e416df85916a {
  meta:
    description = "datamaliciousorder - file 20161206_1c54b181e923a74ff9e7e416df85916a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "826a1e175ba6b53abb1cf9dded26a3a206475035cf913de6a232dd517e8fd1c8"

  strings:
    $s1 = "var vWVq8 = new Function(\"s\", '{var vREm2 = new Date();vREm2[\"setUTCFullYear\"](\"2003\");if (vREm2.getUTCFullYear().toString" ascii
    $s2 = "var vWVq8 = new Function(\"s\", '{var vREm2 = new Date();vREm2[\"setUTCFullYear\"](\"2003\");if (vREm2.getUTCFullYear().toString" ascii
    $s3 = "function vPBg0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vPi2 = s.split(\"##\"); return vPi2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}