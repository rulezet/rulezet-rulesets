rule sig_20161208_d205bca7a8d11d6ca6600eb76f5d5e0e {
  meta:
    description = "datamaliciousorder - file 20161208_d205bca7a8d11d6ca6600eb76f5d5e0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c598a1f03b810056cbb98cd4216f78c686a4775b94ea441a13b39c6792f5c67"

  strings:
    $s1 = "var vUYm5 = new Function(\"vDa8\", '{return vDa8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLn9 = new Function(\"vDa8" ascii
    $s2 = " new Date();vWBf7[\"setUTC\"+\"FullYear\"](\"2003\");if (vWBf7.getUTCFullYear().toString(10) == \"2003\") {var vAa5 = vDa8.split" ascii
    $s3 = "var vUYm5 = new Function(\"vDa8\", '{return vDa8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLn9 = new Function(\"vDa8" ascii
    $s4 = "; return vAa5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}