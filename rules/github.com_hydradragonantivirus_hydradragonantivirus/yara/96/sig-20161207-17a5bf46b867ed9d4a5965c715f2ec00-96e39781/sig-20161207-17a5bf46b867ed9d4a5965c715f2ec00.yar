rule sig_20161207_17a5bf46b867ed9d4a5965c715f2ec00 {
  meta:
    description = "datamaliciousorder - file 20161207_17a5bf46b867ed9d4a5965c715f2ec00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07caf44a7251e0ac15027213d6930ed37d40174b02ddb21339853fa439c3d9cf"

  strings:
    $s1 = "var vFWy2 = new Function(\"vYIk2\", '{return vYIk2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vARd7 = new Function(\"vY" ascii
    $s2 = "6 = new Date();vOs6[\"setUTCFullYear\"](\"2003\");if (vOs6.getUTCFullYear().toString(10) == \"2003\") {var vODv1 = vYIk2.split(" ascii
    $s3 = "; return vODv1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vFWy2 = new Function(\"vYIk2\", '{return vYIk2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vARd7 = new Function(\"vY" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}