rule sig_20161207_ff8afa877411abfb92c83234ed1f9812 {
  meta:
    description = "datamaliciousorder - file 20161207_ff8afa877411abfb92c83234ed1f9812.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4500f11729d187d3fcb119575f4fa64a2d838ea7cfd5e89947012629adbc27b6"

  strings:
    $s1 = " new Date();vVNd6[\"setUTCFullYear\"](\"2003\");if (vVNd6.getUTCFullYear().toString(10) == \"2003\") {var vPJc0 = vQg1.split(\"#" ascii
    $s2 = "var vWq2 = new Function(\"vQg1\", '{return vQg1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZSf9 = new Function(\"vQg1" ascii
    $s3 = "return vPJc0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vWq2 = new Function(\"vQg1\", '{return vQg1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZSf9 = new Function(\"vQg1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}