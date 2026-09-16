rule sig_20161206_43c76b1e1c213c2186dc208105971a40 {
  meta:
    description = "datamaliciousorder - file 20161206_43c76b1e1c213c2186dc208105971a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7fcc92b465bdcc82230366d0383100002e93618fa30f6fe406f06a2b1f9970f"

  strings:
    $s1 = "var vTWx0 = new Function(\"s\", '{var vSJv5 = new Date();vSJv5[\"setUTCFullYear\"](\"2003\");if (vSJv5.getUTCFullYear().toString" ascii
    $s2 = "var vTWx0 = new Function(\"s\", '{var vSJv5 = new Date();vSJv5[\"setUTCFullYear\"](\"2003\");if (vSJv5.getUTCFullYear().toString" ascii
    $s3 = "function vYOx3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vYr2 = s.split(\"##\"); return vYr2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}