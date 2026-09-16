rule sig_20161208_001f549099c47ee7f177586c68119b39 {
  meta:
    description = "datamaliciousorder - file 20161208_001f549099c47ee7f177586c68119b39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f5312930bc442936eab80ed6f0d42f460ef96aaf40e92ed2c07c6a8ffaee788"

  strings:
    $s1 = "8 = new Date();vRFy8[\"setUTC\"+\"FullYear\"](\"2003\");if (vRFy8.getUTCFullYear().toString(10) == \"2003\") {var vMk1 = vSAi2.s" ascii
    $s2 = "var vOn5 = new Function(\"vSAi2\", '{return vSAi2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNDr0 = new Function(\"vSA" ascii
    $s3 = "##\"); return vMk1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vOn5 = new Function(\"vSAi2\", '{return vSAi2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNDr0 = new Function(\"vSA" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}