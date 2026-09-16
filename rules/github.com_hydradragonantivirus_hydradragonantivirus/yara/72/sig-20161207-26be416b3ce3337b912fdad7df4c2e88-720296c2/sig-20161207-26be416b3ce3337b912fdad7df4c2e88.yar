rule sig_20161207_26be416b3ce3337b912fdad7df4c2e88 {
  meta:
    description = "datamaliciousorder - file 20161207_26be416b3ce3337b912fdad7df4c2e88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c06eface2250c09b64b25dd783701e9e5552a40a12800b7a816ebe5e66979e3"

  strings:
    $s1 = "= new Date();vNNs3[\"setUTCFullYear\"](\"2003\");if (vNNs3.getUTCFullYear().toString(10) == \"2003\") {var vGOp9 = vKc8.split(\"" ascii
    $s2 = "var vYDz8 = new Function(\"vKc8\", '{return vKc8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTKw6 = new Function(\"vKc8" ascii
    $s3 = " return vGOp9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vYDz8 = new Function(\"vKc8\", '{return vKc8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTKw6 = new Function(\"vKc8" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}