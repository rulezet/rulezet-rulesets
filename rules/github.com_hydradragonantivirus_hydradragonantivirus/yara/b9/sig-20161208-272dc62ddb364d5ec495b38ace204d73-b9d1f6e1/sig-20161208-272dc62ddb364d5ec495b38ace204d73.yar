rule sig_20161208_272dc62ddb364d5ec495b38ace204d73 {
  meta:
    description = "datamaliciousorder - file 20161208_272dc62ddb364d5ec495b38ace204d73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b513f58cbf8758e95162e593c6729a7845b531c67885a1f8164fc287892d5784"

  strings:
    $s1 = "var vCi6 = new Function(\"vVJa4\", '{return vVJa4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNNz9 = new Function(\"vVJ" ascii
    $s2 = "0 = new Date();vONe0[\"setUTC\"+\"FullYear\"](\"2003\");if (vONe0.getUTCFullYear().toString(10) == \"2003\") {var vKNn1 = vVJa4." ascii
    $s3 = "var vCi6 = new Function(\"vVJa4\", '{return vVJa4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNNz9 = new Function(\"vVJ" ascii
    $s4 = "###\"); return vKNn1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}