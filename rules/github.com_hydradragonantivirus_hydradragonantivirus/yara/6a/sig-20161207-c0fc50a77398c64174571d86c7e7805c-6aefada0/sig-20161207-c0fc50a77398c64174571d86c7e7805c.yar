rule sig_20161207_c0fc50a77398c64174571d86c7e7805c {
  meta:
    description = "datamaliciousorder - file 20161207_c0fc50a77398c64174571d86c7e7805c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0957ae0b3ea61ea1b3f1e191bd6429212766d3579c4ca6aa6d6e74ba1b23dea0"

  strings:
    $s1 = "var vUi5 = new Function(\"vAi4\", '{return vAi4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWv8 = new Function(\"vAi4\"" ascii
    $s2 = "ew Date();vGb6[\"setUTCFullYear\"](\"2003\");if (vGb6.getUTCFullYear().toString(10) == \"2003\") {var vAn6 = vAi4.split(\"####\"" ascii
    $s3 = "var vUi5 = new Function(\"vAi4\", '{return vAi4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWv8 = new Function(\"vAi4\"" ascii
    $s4 = "n vAn6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}