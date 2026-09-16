rule sig_20161207_d58dd1686b23b530b73b6398a9a78890 {
  meta:
    description = "datamaliciousorder - file 20161207_d58dd1686b23b530b73b6398a9a78890.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d7e4d183d52dc47e35e7cdacc8af3e770f450c343861f1cade12d8d7553d91b"

  strings:
    $s1 = "var vGz9 = new Function(\"vYOj4\", '{return vYOj4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXOv5 = new Function(\"vYO" ascii
    $s2 = " = new Date();vVp1[\"setUTCFullYear\"](\"2003\");if (vVp1.getUTCFullYear().toString(10) == \"2003\") {var vFi3 = vYOj4.split(\"#" ascii
    $s3 = "return vFi3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGz9 = new Function(\"vYOj4\", '{return vYOj4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXOv5 = new Function(\"vYO" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}