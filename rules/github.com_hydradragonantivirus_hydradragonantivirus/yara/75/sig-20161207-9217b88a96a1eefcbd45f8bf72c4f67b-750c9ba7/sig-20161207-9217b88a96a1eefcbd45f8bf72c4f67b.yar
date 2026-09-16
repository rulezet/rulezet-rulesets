rule sig_20161207_9217b88a96a1eefcbd45f8bf72c4f67b {
  meta:
    description = "datamaliciousorder - file 20161207_9217b88a96a1eefcbd45f8bf72c4f67b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41161a5170cdf1284538b8028711fe400a4ffa9e94bf7b3f83417fe687042dd9"

  strings:
    $s1 = " new Date();vSe8[\"setUTCFullYear\"](\"2003\");if (vSe8.getUTCFullYear().toString(10) == \"2003\") {var vIo3 = vUg1.split(\"####" ascii
    $s2 = "var vUUz1 = new Function(\"vUg1\", '{return vUg1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUKw8 = new Function(\"vUg1" ascii
    $s3 = "urn vIo3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUUz1 = new Function(\"vUg1\", '{return vUg1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUKw8 = new Function(\"vUg1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}