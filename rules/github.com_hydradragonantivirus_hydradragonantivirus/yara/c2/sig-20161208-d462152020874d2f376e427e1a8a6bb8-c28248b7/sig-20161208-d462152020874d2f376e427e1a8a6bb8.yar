rule sig_20161208_d462152020874d2f376e427e1a8a6bb8 {
  meta:
    description = "datamaliciousorder - file 20161208_d462152020874d2f376e427e1a8a6bb8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38070556812f62208d2991582e5e4160928551dfffe0361efbcac64c25e6c670"

  strings:
    $s1 = "var vUr3 = new Function(\"vCJb7\", '{return vCJb7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJd8 = new Function(\"vCJb" ascii
    $s2 = " = new Date();vSCq8[\"setUTC\"+\"FullYear\"](\"2003\");if (vSCq8.getUTCFullYear().toString(10) == \"2003\") {var vIDs9 = vCJb7.s" ascii
    $s3 = "var vUr3 = new Function(\"vCJb7\", '{return vCJb7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJd8 = new Function(\"vCJb" ascii
    $s4 = "##\"); return vIDs9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}