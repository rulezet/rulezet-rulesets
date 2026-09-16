rule sig_20161207_269e3b41b07ee66992a286141aeb1a70 {
  meta:
    description = "datamaliciousorder - file 20161207_269e3b41b07ee66992a286141aeb1a70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d45fd3dadeea14ba0829e7e838da78049936d7fd7b19768e1d75141a1dfa9210"

  strings:
    $s1 = "var vSl1 = new Function(\"vVc4\", '{return vVc4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNu6 = new Function(\"vVc4\"" ascii
    $s2 = "new Date();vGZu7[\"setUTCFullYear\"](\"2003\");if (vGZu7.getUTCFullYear().toString(10) == \"2003\") {var vFi0 = vVc4.split(\"###" ascii
    $s3 = "var vSl1 = new Function(\"vVc4\", '{return vVc4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNu6 = new Function(\"vVc4\"" ascii
    $s4 = "turn vFi0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}