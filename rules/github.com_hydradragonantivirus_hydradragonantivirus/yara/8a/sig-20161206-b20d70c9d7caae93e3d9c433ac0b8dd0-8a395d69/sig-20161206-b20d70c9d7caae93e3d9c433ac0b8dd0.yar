rule sig_20161206_b20d70c9d7caae93e3d9c433ac0b8dd0 {
  meta:
    description = "datamaliciousorder - file 20161206_b20d70c9d7caae93e3d9c433ac0b8dd0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0e062bd980d28c35eb7b3b0f14f184bc374f60b36031cd3ff856b370ef74dbb"

  strings:
    $s1 = "var vXPr7 = new Function(\"s\", '{var vGi2 = new Date();vGi2[\"setUTCFullYear\"](\"2003\");if (vGi2.getUTCFullYear().toString(10" ascii
    $s2 = "var vXPr7 = new Function(\"s\", '{var vGi2 = new Date();vGi2[\"setUTCFullYear\"](\"2003\");if (vGi2.getUTCFullYear().toString(10" ascii
    $s3 = "function vWFb0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vBy3 = s.split(\"##\"); return vBy3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}