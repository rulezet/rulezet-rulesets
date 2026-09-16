rule sig_20161207_bebdfba234f70626368e2583e91cc519 {
  meta:
    description = "datamaliciousorder - file 20161207_bebdfba234f70626368e2583e91cc519.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be35eed63205f1b54c9588aa2dc0595b1f2adb993661fb28adb3ff1cec324c22"

  strings:
    $s1 = "var vEUs1 = new Function(\"vTFo9\", '{return vTFo9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUr1 = new Function(\"vTF" ascii
    $s2 = " = new Date();vJo6[\"setUTCFullYear\"](\"2003\");if (vJo6.getUTCFullYear().toString(10) == \"2003\") {var vFNq2 = vTFo9.split(\"" ascii
    $s3 = "var vEUs1 = new Function(\"vTFo9\", '{return vTFo9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUr1 = new Function(\"vTF" ascii
    $s4 = " return vFNq2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}