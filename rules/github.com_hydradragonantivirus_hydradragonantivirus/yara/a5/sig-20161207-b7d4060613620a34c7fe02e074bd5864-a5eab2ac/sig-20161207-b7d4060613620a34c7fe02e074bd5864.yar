rule sig_20161207_b7d4060613620a34c7fe02e074bd5864 {
  meta:
    description = "datamaliciousorder - file 20161207_b7d4060613620a34c7fe02e074bd5864.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5af32d786f65cbdfc990e3bafa4493cf369e45ef4494b9c152336b93e8cfc72"

  strings:
    $s1 = "4 = new Date();vJIf4[\"setUTCFullYear\"](\"2003\");if (vJIf4.getUTCFullYear().toString(10) == \"2003\") {var vSIs0 = vNNr4.split" ascii
    $s2 = "var vBy2 = new Function(\"vNNr4\", '{return vNNr4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSIq5 = new Function(\"vNN" ascii
    $s3 = "var vBy2 = new Function(\"vNNr4\", '{return vNNr4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSIq5 = new Function(\"vNN" ascii
    $s4 = "\"); return vSIs0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}