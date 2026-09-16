rule sig_20161207_305538b1470faa456e01b71910b345b9 {
  meta:
    description = "datamaliciousorder - file 20161207_305538b1470faa456e01b71910b345b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d20a4b70711d11634d5103f15a531369e00687eb388c60250fbe2d6adfc4480"

  strings:
    $s1 = "new Date();vQIk2[\"setUTCFullYear\"](\"2003\");if (vQIk2.getUTCFullYear().toString(10) == \"2003\") {var vZZj7 = vTd7.split(\"##" ascii
    $s2 = "var vTj7 = new Function(\"vTd7\", '{return vTd7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGg1 = new Function(\"vTd7\"" ascii
    $s3 = "eturn vZZj7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vTj7 = new Function(\"vTd7\", '{return vTd7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGg1 = new Function(\"vTd7\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}