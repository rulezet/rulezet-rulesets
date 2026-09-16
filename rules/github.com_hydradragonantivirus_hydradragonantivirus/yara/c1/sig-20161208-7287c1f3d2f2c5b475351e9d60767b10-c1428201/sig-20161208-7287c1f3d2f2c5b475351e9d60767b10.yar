rule sig_20161208_7287c1f3d2f2c5b475351e9d60767b10 {
  meta:
    description = "datamaliciousorder - file 20161208_7287c1f3d2f2c5b475351e9d60767b10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac4eb2cdd0067790e7c6489f7d2a690ba8e2ce5fe2187c70480b664fea4f0d02"

  strings:
    $s1 = "var vOXb8 = new Function(\"vNZz8\", '{return vNZz8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYVo0 = new Function(\"vN" ascii
    $s2 = "8 = new Date();vEo8[\"setUTC\"+\"FullYear\"](\"2003\");if (vEo8.getUTCFullYear().toString(10) == \"2003\") {var vNMg0 = vNZz8.sp" ascii
    $s3 = "var vOXb8 = new Function(\"vNZz8\", '{return vNZz8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYVo0 = new Function(\"vN" ascii
    $s4 = "#\"); return vNMg0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}