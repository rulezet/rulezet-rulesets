rule sig_20161207_3767a37fb1f4ce634c211e71b779ca38 {
  meta:
    description = "datamaliciousorder - file 20161207_3767a37fb1f4ce634c211e71b779ca38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95ae475b6f47c1444a2a7fb5a21026c7318cc9bf9fabd771c1cc1017f7d7a4f4"

  strings:
    $s1 = "var vOb3 = new Function(\"vCi8\", '{return vCi8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUDg5 = new Function(\"vCi8" ascii
    $s2 = "new Date();vSb2[\"setUTCFullYear\"](\"2003\");if (vSb2.getUTCFullYear().toString(10) == \"2003\") {var vAk1 = vCi8.split(\"####" ascii
    $s3 = "var vOb3 = new Function(\"vCi8\", '{return vCi8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUDg5 = new Function(\"vCi8" ascii
    $s4 = "rn vAk1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}