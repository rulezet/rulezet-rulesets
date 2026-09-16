rule sig_20161208_92396091121ec19251c0170c0ae7c530 {
  meta:
    description = "datamaliciousorder - file 20161208_92396091121ec19251c0170c0ae7c530.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "357fd41c47dce4a889aa59025f085cd7454eda550248c06403999872fb1ae9f5"

  strings:
    $s1 = "new Date();vSw9[\"setUTC\"+\"FullYear\"](\"2003\");if (vSw9.getUTCFullYear().toString(10) == \"2003\") {var vUCq8 = vPp1.split(" ascii
    $s2 = "var vQp8 = new Function(\"vPp1\", '{return vPp1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFPb4 = new Function(\"vPp1" ascii
    $s3 = "var vQp8 = new Function(\"vPp1\", '{return vPp1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFPb4 = new Function(\"vPp1" ascii
    $s4 = "return vUCq8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}