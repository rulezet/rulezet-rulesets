rule sig_20161206_bd0fcc52db71edf0c9bd79e092d658de {
  meta:
    description = "datamaliciousorder - file 20161206_bd0fcc52db71edf0c9bd79e092d658de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dad2aa5fd7fe24e7d3f7bac8dd2eaa29ebfce262da0d0e045336c1181d5491c"

  strings:
    $s1 = "var vKg1 = new Function(\"s\", '{var vDGi0 = new Date();vDGi0[\"setUTCFullYear\"](\"2003\");if (vDGi0.getUTCFullYear().toString(" ascii
    $s2 = "var vKg1 = new Function(\"s\", '{var vDGi0 = new Date();vDGi0[\"setUTCFullYear\"](\"2003\");if (vDGi0.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vKh4 = s.split(\"##\"); return vKh4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vTRs0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}