rule sig_20161208_b60e547479415159413847f4eea03818 {
  meta:
    description = "datamaliciousorder - file 20161208_b60e547479415159413847f4eea03818.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "433db7dcd02eb7b330d8cf87a751bbe43ff52e2496e40c4c08f7b7e2c4c181d3"

  strings:
    $s1 = "var vFa0 = new Function(\"vDPh5\", '{return vDPh5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVDw0 = new Function(\"vDP" ascii
    $s2 = "0 = new Date();vZSz0[\"setUTC\"+\"FullYear\"](\"2003\");if (vZSz0.getUTCFullYear().toString(10) == \"2003\") {var vTi8 = vDPh5.s" ascii
    $s3 = "var vFa0 = new Function(\"vDPh5\", '{return vDPh5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVDw0 = new Function(\"vDP" ascii
    $s4 = "##\"); return vTi8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}