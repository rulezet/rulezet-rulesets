rule sig_20161208_375543e52a90e778045486021478312f {
  meta:
    description = "datamaliciousorder - file 20161208_375543e52a90e778045486021478312f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aea719e209d39918e6881d2c1cb5af05f86889348cd2084e20f81fc01d99196c"

  strings:
    $s1 = " = new Date();vBQm8[\"setUTC\"+\"FullYear\"](\"2003\");if (vBQm8.getUTCFullYear().toString(10) == \"2003\") {var vAAr3 = vNYj4.s" ascii
    $s2 = "var vTx6 = new Function(\"vNYj4\", '{return vNYj4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZt3 = new Function(\"vNYj" ascii
    $s3 = "var vTx6 = new Function(\"vNYj4\", '{return vNYj4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZt3 = new Function(\"vNYj" ascii
    $s4 = "##\"); return vAAr3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}