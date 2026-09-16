rule sig_20161207_8e3f91f433712401505b44240312151b {
  meta:
    description = "datamaliciousorder - file 20161207_8e3f91f433712401505b44240312151b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e882404654b6fe65f0f7afa7db7358c130effc4232fb2e88e02deb7c1fe63d82"

  strings:
    $s1 = "var vEk0 = new Function(\"vQi2\", '{return vQi2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCo3 = new Function(\"vQi2\"" ascii
    $s2 = "new Date();vAFj4[\"setUTCFullYear\"](\"2003\");if (vAFj4.getUTCFullYear().toString(10) == \"2003\") {var vHBh8 = vQi2.split(\"##" ascii
    $s3 = "eturn vHBh8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEk0 = new Function(\"vQi2\", '{return vQi2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCo3 = new Function(\"vQi2\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}