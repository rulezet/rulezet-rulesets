rule sig_20161208_c1ac1a46733dc63aadb6c4dedbff2f27 {
  meta:
    description = "datamaliciousorder - file 20161208_c1ac1a46733dc63aadb6c4dedbff2f27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e306456d3fba8bc7401803b7578a9b32ba3bb363b28f41231c9632236b4fda33"

  strings:
    $s1 = "var vMCp8 = new Function(\"vWXw0\", '{return vWXw0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGJa3 = new Function(\"vW" ascii
    $s2 = "d2 = new Date();vKJd2[\"setUTC\"+\"FullYear\"](\"2003\");if (vKJd2.getUTCFullYear().toString(10) == \"2003\") {var vZo1 = vWXw0." ascii
    $s3 = "###\"); return vZo1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vMCp8 = new Function(\"vWXw0\", '{return vWXw0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGJa3 = new Function(\"vW" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}