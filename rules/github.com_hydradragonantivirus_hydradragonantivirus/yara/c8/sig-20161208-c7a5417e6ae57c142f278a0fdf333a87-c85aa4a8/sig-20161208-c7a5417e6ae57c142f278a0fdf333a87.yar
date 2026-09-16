rule sig_20161208_c7a5417e6ae57c142f278a0fdf333a87 {
  meta:
    description = "datamaliciousorder - file 20161208_c7a5417e6ae57c142f278a0fdf333a87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a60dff0302e7f89feb9b8115ccd01d32295b4dc5f6d387fa6ad9cf8b7fa9c46f"

  strings:
    $s1 = " new Date();vRAs6[\"setUTC\"+\"FullYear\"](\"2003\");if (vRAs6.getUTCFullYear().toString(10) == \"2003\") {var vSUl8 = vDs9.spli" ascii
    $s2 = "var vNDt3 = new Function(\"vDs9\", '{return vDs9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTe7 = new Function(\"vDs9" ascii
    $s3 = "); return vSUl8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNDt3 = new Function(\"vDs9\", '{return vDs9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTe7 = new Function(\"vDs9" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}