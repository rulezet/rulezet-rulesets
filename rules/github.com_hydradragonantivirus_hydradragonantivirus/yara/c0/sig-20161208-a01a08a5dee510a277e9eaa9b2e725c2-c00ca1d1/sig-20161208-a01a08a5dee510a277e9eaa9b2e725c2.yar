rule sig_20161208_a01a08a5dee510a277e9eaa9b2e725c2 {
  meta:
    description = "datamaliciousorder - file 20161208_a01a08a5dee510a277e9eaa9b2e725c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21b8137c4ee7c96ee66bc7f896d4963ab7453695240b253ef4168183d0a6b65a"

  strings:
    $s1 = "= new Date();vHWb7[\"setUTC\"+\"FullYear\"](\"2003\");if (vHWb7.getUTCFullYear().toString(10) == \"2003\") {var vQYf9 = vWi4.spl" ascii
    $s2 = "var vLQo5 = new Function(\"vWi4\", '{return vWi4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTRw6 = new Function(\"vWi4" ascii
    $s3 = "\"); return vQYf9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vLQo5 = new Function(\"vWi4\", '{return vWi4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTRw6 = new Function(\"vWi4" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}