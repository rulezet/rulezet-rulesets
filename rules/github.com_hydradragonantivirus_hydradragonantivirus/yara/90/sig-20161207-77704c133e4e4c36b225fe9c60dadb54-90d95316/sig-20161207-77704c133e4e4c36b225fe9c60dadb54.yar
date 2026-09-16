rule sig_20161207_77704c133e4e4c36b225fe9c60dadb54 {
  meta:
    description = "datamaliciousorder - file 20161207_77704c133e4e4c36b225fe9c60dadb54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4de3cbfd31e2f9cbdcf9a73d920661b55678dedc48627c5f4ad3a2d6e2b049de"

  strings:
    $s1 = "= new Date();vGKb5[\"setUTCFullYear\"](\"2003\");if (vGKb5.getUTCFullYear().toString(10) == \"2003\") {var vMQo3 = vRq3.split(\"" ascii
    $s2 = "var vABr9 = new Function(\"vRq3\", '{return vRq3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKJm2 = new Function(\"vRq3" ascii
    $s3 = "var vABr9 = new Function(\"vRq3\", '{return vRq3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKJm2 = new Function(\"vRq3" ascii
    $s4 = " return vMQo3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}