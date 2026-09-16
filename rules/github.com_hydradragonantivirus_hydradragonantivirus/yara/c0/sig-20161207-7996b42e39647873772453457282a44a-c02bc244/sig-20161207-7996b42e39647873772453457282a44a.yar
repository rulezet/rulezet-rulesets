rule sig_20161207_7996b42e39647873772453457282a44a {
  meta:
    description = "datamaliciousorder - file 20161207_7996b42e39647873772453457282a44a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a61dc2ebb920a7e5607043923e57fc5bd8e33533be366137f10aa0c4c2cfcfa"

  strings:
    $s1 = "var vGTv4 = new Function(\"vCr5\", '{return vCr5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRm9 = new Function(\"vCr5" ascii
    $s2 = " new Date();vUKe5[\"setUTCFullYear\"](\"2003\");if (vUKe5.getUTCFullYear().toString(10) == \"2003\") {var vZq1 = vCr5.split(\"##" ascii
    $s3 = "var vGTv4 = new Function(\"vCr5\", '{return vCr5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRm9 = new Function(\"vCr5" ascii
    $s4 = "eturn vZq1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}