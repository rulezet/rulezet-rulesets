rule sig_20161206_e3aafbc316309c26f4f4c3f8f8b8ebbc {
  meta:
    description = "datamaliciousorder - file 20161206_e3aafbc316309c26f4f4c3f8f8b8ebbc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d256d779d1976a07b6899a7d21977d5ba3393b614222da5b0028ec6ce881ab5"

  strings:
    $s1 = "var vZTz3 = new Function(\"s\", '{var vRBb0 = new Date();vRBb0[\"setUTCFullYear\"](\"2003\");if (vRBb0.getUTCFullYear().toString" ascii
    $s2 = "var vZTz3 = new Function(\"s\", '{var vRBb0 = new Date();vRBb0[\"setUTCFullYear\"](\"2003\");if (vRBb0.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vEj7 = s.split(\"##\"); return vEj7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vKSx1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}