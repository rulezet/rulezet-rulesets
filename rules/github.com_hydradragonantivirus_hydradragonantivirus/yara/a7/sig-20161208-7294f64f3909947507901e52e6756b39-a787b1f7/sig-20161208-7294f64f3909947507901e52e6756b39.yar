rule sig_20161208_7294f64f3909947507901e52e6756b39 {
  meta:
    description = "datamaliciousorder - file 20161208_7294f64f3909947507901e52e6756b39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c327d7f392c546b7e35457e386623bb46f7f27848e863f544e0907884a6366d3"

  strings:
    $s1 = "3 = new Date();vFHd3[\"setUTC\"+\"FullYear\"](\"2003\");if (vFHd3.getUTCFullYear().toString(10) == \"2003\") {var vDHv6 = vDDs3." ascii
    $s2 = "var vPb1 = new Function(\"vDDs3\", '{return vDDs3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZQd9 = new Function(\"vDD" ascii
    $s3 = "var vPb1 = new Function(\"vDDs3\", '{return vDDs3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZQd9 = new Function(\"vDD" ascii
    $s4 = "###\"); return vDHv6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}