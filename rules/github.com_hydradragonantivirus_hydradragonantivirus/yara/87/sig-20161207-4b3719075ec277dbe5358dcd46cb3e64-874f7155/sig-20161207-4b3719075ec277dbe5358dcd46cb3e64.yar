rule sig_20161207_4b3719075ec277dbe5358dcd46cb3e64 {
  meta:
    description = "datamaliciousorder - file 20161207_4b3719075ec277dbe5358dcd46cb3e64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5db689f7aac28cca739dffa6417e99448938cf8dd808efa8437b31dc45421dd1"

  strings:
    $s1 = " new Date();vLRp7[\"setUTCFullYear\"](\"2003\");if (vLRp7.getUTCFullYear().toString(10) == \"2003\") {var vQGg1 = vTb9.split(\"#" ascii
    $s2 = "var vWx1 = new Function(\"vTb9\", '{return vTb9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYDl2 = new Function(\"vTb9" ascii
    $s3 = "return vQGg1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vWx1 = new Function(\"vTb9\", '{return vTb9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYDl2 = new Function(\"vTb9" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}