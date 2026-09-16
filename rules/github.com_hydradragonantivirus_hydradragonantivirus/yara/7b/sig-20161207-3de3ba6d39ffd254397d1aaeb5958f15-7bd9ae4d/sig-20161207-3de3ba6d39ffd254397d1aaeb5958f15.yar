rule sig_20161207_3de3ba6d39ffd254397d1aaeb5958f15 {
  meta:
    description = "datamaliciousorder - file 20161207_3de3ba6d39ffd254397d1aaeb5958f15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7cee241034615c5c523d8b271e3824df695176bcd37393bbc155e0c35afab32"

  strings:
    $s1 = "ew Date();vYp6[\"setUTCFullYear\"](\"2003\");if (vYp6.getUTCFullYear().toString(10) == \"2003\") {var vOQi8 = vCw1.split(\"####" ascii
    $s2 = "var vMe7 = new Function(\"vCw1\", '{return vCw1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXu0 = new Function(\"vCw1\"" ascii
    $s3 = "var vMe7 = new Function(\"vCw1\", '{return vCw1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXu0 = new Function(\"vCw1\"" ascii
    $s4 = "rn vOQi8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}