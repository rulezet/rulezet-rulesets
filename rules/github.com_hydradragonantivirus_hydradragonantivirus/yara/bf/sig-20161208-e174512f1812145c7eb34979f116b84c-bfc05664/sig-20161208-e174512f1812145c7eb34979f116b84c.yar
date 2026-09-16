rule sig_20161208_e174512f1812145c7eb34979f116b84c {
  meta:
    description = "datamaliciousorder - file 20161208_e174512f1812145c7eb34979f116b84c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cebbc9cf8f99b51dc7910a23e8be95ea68685b5ef76d515131fe8dbda69986ef"

  strings:
    $s1 = " = new Date();vFi3[\"setUTC\"+\"FullYear\"](\"2003\");if (vFi3.getUTCFullYear().toString(10) == \"2003\") {var vGy3 = vHZo9.spli" ascii
    $s2 = "var vWPr0 = new Function(\"vHZo9\", '{return vHZo9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDm5 = new Function(\"vHZ" ascii
    $s3 = "); return vGy3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vWPr0 = new Function(\"vHZo9\", '{return vHZo9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDm5 = new Function(\"vHZ" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}