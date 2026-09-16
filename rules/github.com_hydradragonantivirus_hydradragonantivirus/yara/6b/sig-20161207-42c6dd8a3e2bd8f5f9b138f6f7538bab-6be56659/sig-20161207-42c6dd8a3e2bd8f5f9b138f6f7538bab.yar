rule sig_20161207_42c6dd8a3e2bd8f5f9b138f6f7538bab {
  meta:
    description = "datamaliciousorder - file 20161207_42c6dd8a3e2bd8f5f9b138f6f7538bab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e41448a39453bc37afba86b69c5bd1cd28857ba653bd5c15f1aa1a457b901653"

  strings:
    $s1 = "ew Date();vEr5[\"setUTCFullYear\"](\"2003\");if (vEr5.getUTCFullYear().toString(10) == \"2003\") {var vJp9 = vRs0.split(\"####\"" ascii
    $s2 = "var vPa5 = new Function(\"vRs0\", '{return vRs0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFm5 = new Function(\"vRs0\"" ascii
    $s3 = "n vJp9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vPa5 = new Function(\"vRs0\", '{return vRs0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFm5 = new Function(\"vRs0\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}