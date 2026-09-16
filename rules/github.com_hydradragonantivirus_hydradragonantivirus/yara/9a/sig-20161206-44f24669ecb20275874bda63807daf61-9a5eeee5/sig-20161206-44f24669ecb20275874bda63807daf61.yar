rule sig_20161206_44f24669ecb20275874bda63807daf61 {
  meta:
    description = "datamaliciousorder - file 20161206_44f24669ecb20275874bda63807daf61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "220c9ed44407061efcf161184078ab8c5c3d2d541140e9da572d281d1d793f4a"

  strings:
    $s1 = "var vKOh8 = new Function(\"s\", '{var vIZo4 = new Date();vIZo4[\"setUTCFullYear\"](\"2003\");if (vIZo4.getUTCFullYear().toString" ascii
    $s2 = "var vKOh8 = new Function(\"s\", '{var vIZo4 = new Date();vIZo4[\"setUTCFullYear\"](\"2003\");if (vIZo4.getUTCFullYear().toString" ascii
    $s3 = "function vJLy7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vJa6 = s.split(\"##\"); return vJa6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}