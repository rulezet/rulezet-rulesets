rule sig_20161208_40f300a67ca07dd009f25eb40930dd8d {
  meta:
    description = "datamaliciousorder - file 20161208_40f300a67ca07dd009f25eb40930dd8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f58cd76dc21396934f78f1c13ffb9e083aee91ab1f86f49c6197f3ab65cdebd"

  strings:
    $s1 = "var vZYl2 = new Function(\"vXd6\", '{return vXd6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBi6 = new Function(\"vXd6" ascii
    $s2 = " new Date();vTKl3[\"setUTC\"+\"FullYear\"](\"2003\");if (vTKl3.getUTCFullYear().toString(10) == \"2003\") {var vCn7 = vXd6.split" ascii
    $s3 = "; return vCn7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vZYl2 = new Function(\"vXd6\", '{return vXd6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBi6 = new Function(\"vXd6" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}