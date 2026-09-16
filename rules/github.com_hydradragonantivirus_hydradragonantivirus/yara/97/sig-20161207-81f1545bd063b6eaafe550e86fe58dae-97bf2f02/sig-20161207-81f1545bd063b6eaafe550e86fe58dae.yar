rule sig_20161207_81f1545bd063b6eaafe550e86fe58dae {
  meta:
    description = "datamaliciousorder - file 20161207_81f1545bd063b6eaafe550e86fe58dae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab5a616ed0b5fff2af1341fa7d36bffc5f877d1145aa61e96776cfe9b960a6ff"

  strings:
    $s1 = "var vWDy3 = new Function(\"vTYf6\", '{return vTYf6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMBz3 = new Function(\"vT" ascii
    $s2 = "z8 = new Date();vXVz8[\"setUTCFullYear\"](\"2003\");if (vXVz8.getUTCFullYear().toString(10) == \"2003\") {var vAf4 = vTYf6.split" ascii
    $s3 = "\"); return vAf4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vWDy3 = new Function(\"vTYf6\", '{return vTYf6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMBz3 = new Function(\"vT" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}