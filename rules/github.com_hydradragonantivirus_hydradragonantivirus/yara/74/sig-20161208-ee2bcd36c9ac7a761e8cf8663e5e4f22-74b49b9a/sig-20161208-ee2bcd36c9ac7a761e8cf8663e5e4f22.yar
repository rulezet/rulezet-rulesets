rule sig_20161208_ee2bcd36c9ac7a761e8cf8663e5e4f22 {
  meta:
    description = "datamaliciousorder - file 20161208_ee2bcd36c9ac7a761e8cf8663e5e4f22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "144de00c3ac9373089eb01ed192bb412008bf3300941deb6f72a5fe4caf0a767"

  strings:
    $s1 = " = new Date();vYs3[\"setUTC\"+\"FullYear\"](\"2003\");if (vYs3.getUTCFullYear().toString(10) == \"2003\") {var vCYl4 = vNUp7.spl" ascii
    $s2 = "var vOXs2 = new Function(\"vNUp7\", '{return vNUp7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFx8 = new Function(\"vNU" ascii
    $s3 = "var vOXs2 = new Function(\"vNUp7\", '{return vNUp7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFx8 = new Function(\"vNU" ascii
    $s4 = "\"); return vCYl4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}