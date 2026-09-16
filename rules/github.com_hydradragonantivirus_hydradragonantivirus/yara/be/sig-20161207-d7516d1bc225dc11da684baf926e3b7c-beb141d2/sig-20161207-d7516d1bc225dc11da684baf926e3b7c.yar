rule sig_20161207_d7516d1bc225dc11da684baf926e3b7c {
  meta:
    description = "datamaliciousorder - file 20161207_d7516d1bc225dc11da684baf926e3b7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edef30887e07de3d8be48e79e7f0e22617311188b61aefc4efcec4be78363ffa"

  strings:
    $s1 = "var vAo9 = new Function(\"vHh7\", '{return vHh7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGx2 = new Function(\"vHh7\"" ascii
    $s2 = "new Date();vNHz7[\"setUTCFullYear\"](\"2003\");if (vNHz7.getUTCFullYear().toString(10) == \"2003\") {var vMt2 = vHh7.split(\"###" ascii
    $s3 = "turn vMt2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vAo9 = new Function(\"vHh7\", '{return vHh7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGx2 = new Function(\"vHh7\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}