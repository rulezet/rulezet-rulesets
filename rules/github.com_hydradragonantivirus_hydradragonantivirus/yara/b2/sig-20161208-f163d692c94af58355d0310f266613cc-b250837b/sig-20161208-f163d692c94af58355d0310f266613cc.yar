rule sig_20161208_f163d692c94af58355d0310f266613cc {
  meta:
    description = "datamaliciousorder - file 20161208_f163d692c94af58355d0310f266613cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b736e985bd3f9de21967142333551328128690602cf4abebf03299432f70be94"

  strings:
    $s1 = "var vXd9 = new Function(\"vIVw6\", '{return vIVw6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVk4 = new Function(\"vIVw" ascii
    $s2 = " = new Date();vYYp2[\"setUTC\"+\"FullYear\"](\"2003\");if (vYYp2.getUTCFullYear().toString(10) == \"2003\") {var vOb4 = vIVw6.sp" ascii
    $s3 = "var vXd9 = new Function(\"vIVw6\", '{return vIVw6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVk4 = new Function(\"vIVw" ascii
    $s4 = "#\"); return vOb4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}