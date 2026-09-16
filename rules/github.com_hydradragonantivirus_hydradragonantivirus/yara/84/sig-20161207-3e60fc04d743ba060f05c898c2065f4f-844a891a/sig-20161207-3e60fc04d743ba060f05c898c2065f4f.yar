rule sig_20161207_3e60fc04d743ba060f05c898c2065f4f {
  meta:
    description = "datamaliciousorder - file 20161207_3e60fc04d743ba060f05c898c2065f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e73cabaab2bfe2a5803e66a87958597312ce462940bd26f168fefe7b386221e9"

  strings:
    $s1 = " new Date();vKVy9[\"setUTCFullYear\"](\"2003\");if (vKVy9.getUTCFullYear().toString(10) == \"2003\") {var vDUx4 = vTu6.split(\"#" ascii
    $s2 = "var vVPb7 = new Function(\"vTu6\", '{return vTu6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMf1 = new Function(\"vTu6" ascii
    $s3 = "return vDUx4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vVPb7 = new Function(\"vTu6\", '{return vTu6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMf1 = new Function(\"vTu6" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}