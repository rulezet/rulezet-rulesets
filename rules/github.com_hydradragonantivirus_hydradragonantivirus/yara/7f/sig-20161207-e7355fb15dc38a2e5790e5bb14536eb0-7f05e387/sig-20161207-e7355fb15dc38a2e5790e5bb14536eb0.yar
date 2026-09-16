rule sig_20161207_e7355fb15dc38a2e5790e5bb14536eb0 {
  meta:
    description = "datamaliciousorder - file 20161207_e7355fb15dc38a2e5790e5bb14536eb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96498cde47bf309f0f0f2f46f3917166a69d288b816d0722aae94dab5febee40"

  strings:
    $s1 = "= new Date();vSd4[\"setUTCFullYear\"](\"2003\");if (vSd4.getUTCFullYear().toString(10) == \"2003\") {var vMt7 = vPTi7.split(\"##" ascii
    $s2 = "var vMn6 = new Function(\"vPTi7\", '{return vPTi7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCz7 = new Function(\"vPTi" ascii
    $s3 = "var vMn6 = new Function(\"vPTi7\", '{return vPTi7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCz7 = new Function(\"vPTi" ascii
    $s4 = "eturn vMt7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}