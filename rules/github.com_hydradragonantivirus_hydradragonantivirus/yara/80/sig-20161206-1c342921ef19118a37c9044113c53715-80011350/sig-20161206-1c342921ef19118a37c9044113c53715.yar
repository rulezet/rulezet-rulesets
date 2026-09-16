rule sig_20161206_1c342921ef19118a37c9044113c53715 {
  meta:
    description = "datamaliciousorder - file 20161206_1c342921ef19118a37c9044113c53715.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c72fe158e1d1d69c46129338a548638ea1efbbbc4741c255eeda37f7bb60aec4"

  strings:
    $s1 = "var vVOd9 = new Function(\"s\", '{var vZVc4 = new Date();vZVc4[\"setUTCFullYear\"](\"2003\");if (vZVc4.getUTCFullYear().toString" ascii
    $s2 = "var vVOd9 = new Function(\"s\", '{var vZVc4 = new Date();vZVc4[\"setUTCFullYear\"](\"2003\");if (vZVc4.getUTCFullYear().toString" ascii
    $s3 = "function vYWx1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vSTm3 = s.split(\"##\"); return vSTm3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}