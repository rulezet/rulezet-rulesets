rule sig_20161208_6d184fed2a13d77a8ee8c63dd5cf9d76 {
  meta:
    description = "datamaliciousorder - file 20161208_6d184fed2a13d77a8ee8c63dd5cf9d76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08d39a19cc8835e20d6db8e898f77e57bf3f58b9a5340f6e20be026645578535"

  strings:
    $s1 = "var vFMt6 = new Function(\"vWLs6\", '{return vWLs6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMTu8 = new Function(\"vW" ascii
    $s2 = "m0 = new Date();vIBm0[\"setUTC\"+\"FullYear\"](\"2003\");if (vIBm0.getUTCFullYear().toString(10) == \"2003\") {var vHDu6 = vWLs6" ascii
    $s3 = "####\"); return vHDu6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vFMt6 = new Function(\"vWLs6\", '{return vWLs6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMTu8 = new Function(\"vW" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}