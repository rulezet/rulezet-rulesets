rule sig_20161207_c17ac5caf221ae037e5e1c20fcd7a7be {
  meta:
    description = "datamaliciousorder - file 20161207_c17ac5caf221ae037e5e1c20fcd7a7be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4363fec9f0112216085838c1f6e453a0dff19e9fe380c4a18b9be608ad6c854"

  strings:
    $s1 = "var vEm2 = new Function(\"vJd9\", '{return vJd9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWCy3 = new Function(\"vJd9" ascii
    $s2 = "new Date();vAl2[\"setUTCFullYear\"](\"2003\");if (vAl2.getUTCFullYear().toString(10) == \"2003\") {var vOa9 = vJd9.split(\"####" ascii
    $s3 = "rn vOa9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEm2 = new Function(\"vJd9\", '{return vJd9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWCy3 = new Function(\"vJd9" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}