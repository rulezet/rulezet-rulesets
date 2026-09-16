rule sig_20161208_5a6e57bf31c042365d92a2bbe1e07f36 {
  meta:
    description = "datamaliciousorder - file 20161208_5a6e57bf31c042365d92a2bbe1e07f36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65f9992efc5e8bc8593a3d2d5a3279a0e900f7eaa96f515d3f3448bfe0f6988c"

  strings:
    $s1 = "var vTDa2 = new Function(\"vCLk2\", '{return vCLk2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPa5 = new Function(\"vCL" ascii
    $s2 = " = new Date();vXj0[\"setUTC\"+\"FullYear\"](\"2003\");if (vXj0.getUTCFullYear().toString(10) == \"2003\") {var vWj3 = vCLk2.spli" ascii
    $s3 = "var vTDa2 = new Function(\"vCLk2\", '{return vCLk2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPa5 = new Function(\"vCL" ascii
    $s4 = "); return vWj3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}